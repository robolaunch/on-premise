#!/bin/bash
set -e;

ARCH=$(dpkg --print-architecture);
TIMESTAMP=$(date +%s);
DIR_PATH=/root/robolaunch/plugins/robotics/components
mkdir -p $DIR_PATH;
OUTPUT_FILE="$DIR_PATH/out_$TIMESTAMP.log";
touch $OUTPUT_FILE;

exec 3>&1 >$OUTPUT_FILE 2>&1;
print_global_log () {
    echo -e "${GREEN}$1${NC}" >&3;
}
print_log () {
    echo -e "${GREEN}$1${NC}";
}
print_err () {
    echo -e "${RED}Error: $1${NC}" >&3;
    exit 1;
}

ORGANIZATION=org_$org_name_plain
TEAM=org_$org_name_plain
REGION=$region_plain
CLOUD_INSTANCE=$cloud_instance
CLOUD_INSTANCE_ALIAS=$cloud_instance_alias
CLUSTER_DOMAIN=$cloud_instance
DESIRED_CLUSTER_CIDR=10.200.1.0/24
DESIRED_SERVICE_CIDR=10.200.2.0/24
DOMAIN=$root_domain
SERVER_URL=$CLOUD_INSTANCE.$DOMAIN
GITHUB_PATH=$github_pat

BLUE='\033[0;34m';
GREEN='\033[0;32m';
RED='\033[0;31m';
NC='\033[0m';

export KUBECONFIG="/etc/rancher/k3s/k3s.yaml";

set_cluster_root_domain () {
    CLUSTER_ROOT_DOMAIN=$(kubectl get cm coredns -n kube-system -o jsonpath="{.data.Corefile}" \
        | grep ".local " \
        | awk -F ' ' '{print $2}');
}
set_organization () {
    if [[ -z "${ORGANIZATION}" ]]; then
        print_err "ORGANIZATION should be set";
    else
        ORGANIZATION=$ORGANIZATION;
    fi
}
set_team () {
    if [[ -z "${TEAM}" ]]; then
        print_err "TEAM should be set";
    else
        TEAM=$TEAM;
    fi
}
set_region () {
    if [[ -z "${REGION}" ]]; then
        print_err "REGION should be set";
    else
        REGION=$REGION;
    fi
}
set_cloud_instance () {
    if [[ -z "${CLOUD_INSTANCE}" ]]; then
        print_err "CLOUD_INSTANCE should be set";
    else
        CLOUD_INSTANCE=$CLOUD_INSTANCE;
    fi
}
set_cloud_instance_alias () {
    if [[ -z "${CLOUD_INSTANCE_ALIAS}" ]]; then
        print_err "CLOUD_INSTANCE_ALIAS should be set";
    else
        CLOUD_INSTANCE_ALIAS=$CLOUD_INSTANCE_ALIAS;
    fi
}
set_desired_cluster_cidr () {
    if [[ -z "${DESIRED_CLUSTER_CIDR}" ]]; then
        print_err "DESIRED_CLUSTER_CIDR should be set";
    else
        DESIRED_CLUSTER_CIDR=$DESIRED_CLUSTER_CIDR;
    fi
}
set_desired_service_cidr () {
    if [[ -z "${DESIRED_SERVICE_CIDR}" ]]; then
        print_err "DESIRED_SERVICE_CIDR should be set";
    else
        DESIRED_SERVICE_CIDR=$DESIRED_SERVICE_CIDR;
    fi
}
set_public_ip () {
    if [[ -z "${PUBLIC_IP}" ]]; then
        PUBLIC_IP=$(curl https://ipinfo.io/ip);
    else
        PUBLIC_IP=$PUBLIC_IP;
    fi
}
check_api_server_url () {
    set_public_ip
    CLOUD_INSTANCE_API_SERVER_URL="$SERVER_URL:6443";
}
check_node_name () {
    NODE_NAME=$(kubectl get nodes -l node-role.kubernetes.io/master -o 'jsonpath={.items[*].metadata.name}');
}
check_cluster_cidr () {
    check_node_name;
    CLOUD_INSTANCE_CLUSTER_CIDR=$(kubectl get nodes $NODE_NAME -o jsonpath='{.spec.podCIDR}');
}
check_service_cidr () {
    CLOUD_INSTANCE_SERVICE_CIDR=$(echo '{"apiVersion":"v1","kind":"Service","metadata":{"name":"tst"},"spec":{"clusterIP":"1.1.1.1","ports":[{"port":443}]}}' | kubectl apply -f - 2>&1 | sed 's/.*valid IPs is //');
}
check_inputs () {
    set_organization;
    set_team;
    set_region;
    set_cloud_instance;
    set_cloud_instance_alias;
    set_desired_cluster_cidr;
    set_desired_service_cidr;
}
get_versioning_map () {
    wget -P $DIR_PATH https://raw.githubusercontent.com/robolaunch/robolaunch/main/platform.yaml;
}
opening () {
    apt-get update 2>/dev/null 1>/dev/null;
    apt-get install -y figlet 2>/dev/null 1>/dev/null; 
    figlet 'robolaunch' -f slant;
}
check_if_root () {
    if [ $USER != "root" ]; then
        print_err "You should switch to root using \"sudo -i\" before setup."
    fi
}
wait_for_apt_db_lock () {
    while [ "$?" -ne 0 ]
    do
        echo -n "waiting for apt database lock";
        sleep 3;
        apt-get check >/dev/null 2>&1;
    done
}
install_pre_tools () {
    print_log "Installing Tools...";
    # apt packages
    apt-get update;
    apt-get install -y curl wget net-tools;
    # install yq
    wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${ARCH};
    chmod a+x /usr/local/bin/yq;
}
check_cluster () {
    check_api_server_url;
    check_cluster_cidr;
    check_service_cidr;
    set_public_ip;
    curl -vk --resolve $PUBLIC_IP:6443:127.0.0.1  https://$PUBLIC_IP:6443/ping;
	  cp /etc/rancher/k3s/k3s.yaml $DIR_PATH/k3s.yaml;
	  chmod 777 $DIR_PATH/k3s.yaml;
    READY_NODE_COUNT="0";
    while [ "$READY_NODE_COUNT" != "1" ]
    do
        echo -n "no node found";
        sleep 3;
        READY_NODE_COUNT=$(kubectl get nodes | grep "Ready" | wc -l);
    done
}
label_node () {
    check_node_name;
    kubectl label --overwrite=true node $NODE_NAME \
      robolaunch.io/robotics-plugin="true";
}
add_helm_repositories () {
    helm repo add robolaunch https://robolaunch.github.io/charts;
}
install_operator_suite () {

    # deploying connection hub operator

    CHO_HELM_INSTALL_SUCCEEDED="false"
    while [ "$CHO_HELM_INSTALL_SUCCEEDED" != "true" ]
    do 
        CHO_HELM_INSTALL_SUCCEEDED="true"
        helm upgrade -i \
            connection-hub-operator robolaunch/connection-hub-operator \
            --namespace connection-hub-system \
            --create-namespace \
            --version $CONNECTION_HUB_OPERATOR_CHART_VERSION || CHO_HELM_INSTALL_SUCCEEDED="false";
        sleep 1;
    done

    # deploying fleet operator

    FO_HELM_INSTALL_SUCCEEDED="false"
    while [ "$FO_HELM_INSTALL_SUCCEEDED" != "true" ]
    do 
        FO_HELM_INSTALL_SUCCEEDED="true"
        helm upgrade -i \
            fleet-operator robolaunch/fleet-operator \
            --namespace fleet-system \
            --create-namespace \
            --version $FLEET_OPERATOR_CHART_VERSION || FO_HELM_INSTALL_SUCCEEDED="false";
        sleep 1;
    done
    sleep 5;
}
federate_metrics_exporter () {
    wget https://github.com/kubernetes-retired/kubefed/releases/download/v0.9.2/kubefedctl-0.9.2-linux-amd64.tgz;
    tar -xvzf kubefedctl-0.9.2-linux-amd64.tgz;
    mv ./kubefedctl /usr/local/bin/;
    kubefedctl enable namespaces metricsexporters;
}
deploy_connection_hub () {
    check_cluster
    wget -P $DIR_PATH $CONNECTION_HUB_RESOURCE_URL;
    CH_PATH=$DIR_PATH/ch-ci.yaml;
    yq e -i ".metadata.labels.\"robolaunch.io/cloud-instance\" = \"$CLOUD_INSTANCE\"" $CH_PATH;
    yq e -i ".metadata.labels.\"robolaunch.io/cloud-instance-alias\" = \"$CLOUD_INSTANCE_ALIAS\"" $CH_PATH;
    yq e -i ".spec.submarinerSpec.apiServerURL = \"$CLOUD_INSTANCE_API_SERVER_URL\"" $CH_PATH;
    yq e -i ".spec.submarinerSpec.clusterCIDR = \"$CLOUD_INSTANCE_CLUSTER_CIDR\"" $CH_PATH;
    yq e -i ".spec.submarinerSpec.serviceCIDR = \"$CLOUD_INSTANCE_SERVICE_CIDR\"" $CH_PATH;
    
    CH_INSTALL_SUCCEEDED="false"
    while [ "$CH_INSTALL_SUCCEEDED" != "true" ]
    do 
        CH_INSTALL_SUCCEEDED="true"
        kubectl apply -f -P $DIR_PATH/ch-ci.yaml || CH_INSTALL_SUCCEEDED="false";
        sleep 3;
    done

    check_connection_hub_phase;
}
check_connection_hub_phase () {
    while [ true ]
    do
        CH_PHASE=$(kubectl get connectionhub connection-hub -o jsonpath=\"{.status.phase}\" | yq -P);
        if [ "$CH_PHASE" = "ReadyForOperation" ]; then
            print_log "Connection hub ready";
            break;
        fi
        print_log "Checking connection hub phase -> $CH_PHASE";
        sleep 3;
    done
}


##############################################################
##############################################################
##############################################################

print_global_log "Waiting for the preflight checks...";
(check_if_root)
print_global_log "Waiting for the apt database lock...";
(wait_for_apt_db_lock)
(install_pre_tools)
(get_versioning_map)
sleep 3
if [[ -z "${PLATFORM_VERSION}" ]]; then
    PLATFORM_VERSION=$(yq '.versions[0].version' < $DIR_PATH/platform.yaml)
fi
sleep 3
VERSION_SELECTOR_STR='.versions[] | select(.version == "'"$PLATFORM_VERSION"'")'
K3S_VERSION=v$(yq ''"${VERSION_SELECTOR_STR}"' | .roboticsCloud.kubernetes.version' < $DIR_PATH/platform.yaml)
CERT_MANAGER_VERSION=$(yq ''"${VERSION_SELECTOR_STR}"' | .roboticsCloud.kubernetes.components.cert-manager.version' < $DIR_PATH/platform.yaml)
CONNECTION_HUB_OPERATOR_CHART_VERSION=$(yq ''"${VERSION_SELECTOR_STR}"' | .roboticsCloud.kubernetes.operators.connectionHub.helm.version' < $DIR_PATH/platform.yaml)
CONNECTION_HUB_RESOURCE_URL=$(yq ''"${VERSION_SELECTOR_STR}"' | .roboticsCloud.kubernetes.operators.connectionHub.resources.cloudInstance' < $DIR_PATH/platform.yaml)
ROBOT_OPERATOR_CHART_VERSION=$(yq ''"${VERSION_SELECTOR_STR}"' | .roboticsCloud.kubernetes.operators.robot.helm.version' < $DIR_PATH/platform.yaml)
FLEET_OPERATOR_CHART_VERSION=$(yq ''"${VERSION_SELECTOR_STR}"' | .roboticsCloud.kubernetes.operators.fleet.helm.version' < $DIR_PATH/platform.yaml)
opening >&3
(check_inputs)
print_global_log "Checking cluster health...";
(check_cluster)
print_global_log "Labeling node...";
(label_node)
print_global_log "Adding Helm repositories...";
(add_helm_repositories)
print_global_log "Installing robolaunch Operator Suite...";
(install_operator_suite)
print_global_log "Deploying Connection Hub...";
(deploy_connection_hub)
print_global_log "Checking Connection Hub phase...";
(check_connection_hub_phase)