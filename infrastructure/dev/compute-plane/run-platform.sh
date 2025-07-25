#!/bin/bash
set -e;
export DEBIAN_FRONTEND=noninteractive

ARCH=$(dpkg --print-architecture);
TIMESTAMP=$(date +%s);
DIR_PATH=/root/robolaunch;
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
GROUP=org_$org_name_plain"_admin"
GROUP_SUPER_ADMIN=org_$org_name_plain"_super_admin"
TEAM=$cloud_instance
REGION=$region_plain
CLOUD_INSTANCE=$cloud_instance
CLOUD_INSTANCE_ALIAS=$cloud_instance_alias
CLUSTER_DOMAIN=$cloud_instance
DESIRED_CLUSTER_CIDR=10.200.1.0/24
DESIRED_SERVICE_CIDR=10.200.2.0/24
OIDC_URL=https://$identity_subdomain.$root_domain/auth/realms/robo-realm
OIDC_ORGANIZATION_CLIENT_ID=operator-client
OIDC_ORGANIZATION_CLIENT_SECRET=$org_client_secret
COOKIE_SECRET=MFlZN1J5eitIdUplckJLaW55YlF6UjVlQ3lneFJBcEU=
DOMAIN=$root_domain
SERVER_URL=$CLOUD_INSTANCE.$DOMAIN
GITHUB_PATH=$github_pat
NVIDIA_DRIVER_VERSION="550" # $nvidia_driver_version

############## Optional Parameters ##############
SELF_SIGNED_CERT=$self_signed_cert
TZ_CONTINENT=$tz_continent
TZ_CITY=$tz_city
CONTROL_PLANE_HOST_ENTRY=$control_plane_host_entry
COMPUTE_PLANE_HOST_ENTRY=$compute_plane_host_entry
CONTROL_COMPUTE_PLANE_HOST_ENTRY=$control_compute_plane_host_entry
if [[ -z "${available_mig_instance}" ]]; then
    print_log "Skipping MIG configuration..."
else
    MIG_INSTANCE_TYPE=$available_mig_instance
fi
if [[ -z "${mig_strategy}" ]]; then
    MIG_STRATEGY=none
else
    MIG_STRATEGY=$mig_strategy
fi
#################################################

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
make_life_more_beautiful () {
    echo "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml" >> ~/.bashrc;
    echo "export KUBE_EDITOR=nano" >> ~/.bashrc;
    echo "alias k=\"kubectl\"" >> ~/.bashrc;
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
check_firewall () {
    if command -v ufw &> /dev/null; then
        status=$(ufw status | grep -i "Status:")

        if [[ $status == *"Status: active"* ]]; then
            print_err "Firewall is active. Deactivate it using \"ufw disable\" before startup."
        elif [[ $status == *"Status: inactive"* ]]; then
            sleep 1
            # echo "Firewall is inactive."
        else
            print_err "Unable to determine firewall status."
        fi
    else
        # UFW yoksa kontrolü atla, istersen bilgi mesajı basabilirsin:
        # echo "UFW not installed, skipping firewall check."
        sleep 0.5
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
configuring_ssh () {
    SSHD_CONFIG_PATH="/etc/ssh/sshd_config"

    # SSH sunucu yüklü mü kontrol et, yoksa kur
    if ! command -v sshd &> /dev/null; then
        echo "OpenSSH server not found. Installing..."
        apt update && apt install -y openssh-server
    fi

    # sshd_config mevcut mu kontrol et
    if [ ! -f "$SSHD_CONFIG_PATH" ]; then
        echo "sshd_config not found, creating default config."
        mkdir -p /etc/ssh
        ssh-keygen -A  # host keyleri oluştur
        systemctl enable ssh
        systemctl start ssh
    fi

    # PubkeyAcceptedKeyTypes satırını kontrol et ve ekle
    if grep -q "PubkeyAcceptedKeyTypes=+ssh-rsa" "$SSHD_CONFIG_PATH"; then
        echo "skipping configuring SSH since it's already configured"
    else
        echo "Configuring SSH to accept ssh-rsa pubkey type."
        echo "PubkeyAcceptedKeyTypes=+ssh-rsa" >> "$SSHD_CONFIG_PATH"
        systemctl restart ssh
    fi
}
create_directories () {
    mkdir -p $DIR_PATH/coredns;
    mkdir -p $DIR_PATH/metrics-server;
    mkdir -p $DIR_PATH/openebs;
    mkdir -p $DIR_PATH/cert-manager;
    mkdir -p $DIR_PATH/nvidia-device-plugin;
    mkdir -p $DIR_PATH/nvidia-dcgm-exporter;
    mkdir -p $DIR_PATH/ingress-nginx;
    mkdir -p $DIR_PATH/oauth2-proxy;
    mkdir -p $DIR_PATH/robot-operator;
    mkdir -p $DIR_PATH/filemanager;

    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/coredns https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/coredns-1.24.5.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/coredns https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/coredns.yaml
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/metrics-server https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/metrics-server-3.11.0.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/openebs https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/openebs-3.8.0.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/nvidia-device-plugin https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/nvidia-device-plugin-0.14.2.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/nvidia-dcgm-exporter https://github.com/robolaunch/on-premise/releases/download/0.1.2-prerelease.10/dcgm-exporter-3.2.0.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/cert-manager https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/cert-manager-v1.12.4.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/ingress-nginx https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/ingress-nginx-4.7.1.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/oauth2-proxy https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/oauth2-proxy-6.17.0.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/robot-operator https://github.com/robolaunch/charts/releases/download/robot-operator-$ROBOT_OPERATOR_CHART_VERSION/robot-operator-$ROBOT_OPERATOR_CHART_VERSION.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/filemanager https://github.com/robolaunch/on-premise/releases/download/0.1.2-prerelease.10/filebrowser-relay-resources.yaml
}
install_pre_tools () {
    print_log "Installing Tools...";
    # apt packages
    apt-get update;
    apt-get install -y git curl wget net-tools;
    # install yq
    wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${ARCH};
    chmod a+x /usr/local/bin/yq;
}
install_post_tools () {
    print_log "Installing Tools...";
    # helm
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash;
}
set_up_nvidia_container_runtime () {
    print_log "Setting up NVIDIA container runtime...";
    DEBIAN_FRONTEND=noninteractive
    apt-get update;
    apt-get install -y gnupg linux-headers-$(uname -r);
    apt-get install -y --no-install-recommends nvidia-driver-$NVIDIA_DRIVER_VERSION;
    distribution=$(. /etc/os-release; echo $ID$VERSION_ID | sed -e 's/\.//g')
    curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-docker-keyring.gpg
    curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list |     sed 's/jammy/noble/' | sudo tee /etc/apt/sources.list.d/nvidia-docker.list
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list |   sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' |   sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
    sudo apt-get update
    sudo apt install nvidia-container-runtime -y
    sleep 2
    driver_pkg=$(dpkg -l | grep -i '^ii' | grep -E 'nvidia-driver-[0-9]+' | awk '{print $2}')
    if [ -n "$driver_pkg" ]; then
        echo "Holding NVIDIA driver package: $driver_pkg"
        sudo apt-mark hold "$driver_pkg"
    else
        echo "No NVIDIA driver package found."
    fi
}
copy_start_script () {
    echo "#!/bin/bash
sleep 30
wan_ip=\$(curl https://ipinfo.io/ip)
export wan_ip=\$wan_ip
curl -vk --resolve \$wan_ip:6443:127.0.0.1 https://\$wan_ip:6443/ping" > $DIR_PATH/start_script.sh
        chmod +x $DIR_PATH/start_script.sh
        cp  $DIR_PATH/start_script.sh /var/lib/cloud/scripts/per-boot/initial-script.sh
}
set_up_k3s () {
    CERT_ARG=""

    if [[ -z "${SELF_SIGNED_CERT}" ]]; then
        CERT_ARG="";
    else
        CERT_ARG="--kube-apiserver-arg oidc-ca-file=/root/ca.crt"
    fi

    curl -sfL https://get.k3s.io | \
        INSTALL_K3S_VERSION=v1.31.10+k3s1 \
        K3S_KUBECONFIG_MODE="644" \
        INSTALL_K3S_EXEC="\
          --cluster-cidr=$DESIRED_CLUSTER_CIDR \
          --service-cidr=$DESIRED_SERVICE_CIDR \
          --cluster-domain=$CLUSTER_DOMAIN.local \
          --disable-network-policy \
          --disable=coredns \
          --disable=traefik \
          --disable=local-storage \
          --disable=metrics-server \
          --pause-image=quay.io/robolaunchio/mirrored-pause:3.6 \
          --kube-apiserver-arg \
            oidc-issuer-url=$OIDC_URL \
          --kube-apiserver-arg \
            oidc-client-id=$OIDC_ORGANIZATION_CLIENT_ID \
          --kube-apiserver-arg \
            oidc-username-claim=preferred_username \
          --kube-apiserver-arg \
            oidc-groups-claim=groups \
          $CERT_ARG" sh -;
    sleep 5;
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
      robolaunch.io/platform=$PLATFORM_VERSION \
      robolaunch.io/organization=$ORGANIZATION \
      robolaunch.io/region=$REGION \
      robolaunch.io/team=$TEAM \
      robolaunch.io/cloud-instance=$CLOUD_INSTANCE \
      robolaunch.io/cloud-instance-alias=$CLOUD_INSTANCE_ALIAS \
      robolaunch.io/mig-instance-type=$MIG_INSTANCE_TYPE \
      robolaunch.io/tz-continent=$TZ_CONTINENT \
      robolaunch.io/tz-city=$TZ_CITY \
      robolaunch.io/domain=$DOMAIN \
      submariner.io/gateway="true";
}
install_openebs () {
    echo "image:
  repository: quay.io/
helper:
  image: robolaunchio/linux-utils
  imageTag: 3.4.0
ndm:
  image: robolaunchio/node-disk-manager
  imageTag: 2.1.0
ndmOperator:
  image: robolaunchio/node-disk-operator
  imageTag: 2.1.0
localprovisioner:
  image: robolaunchio/provisioner-localpv
  imageTag: 3.4.0" > $DIR_PATH/openebs/values.yaml;
    helm upgrade --install \
      openebs $DIR_PATH/openebs/openebs-3.8.0.tgz \
      --namespace openebs \
      --create-namespace \
      -f $DIR_PATH/openebs/values.yaml;
    sleep 5;
    kubectl patch storageclass openebs-hostpath -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}';
}
install_nvidia_runtime_class () {
    cat << EOF | kubectl apply -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
EOF
}
install_nvidia_device_plugin () {
    echo "image:
  repository: quay.io/robolaunchio/k8s-device-plugin
  tag: v0.14.2" > $DIR_PATH/nvidia-device-plugin/values.yaml;
    if [[ -z "${MIG_INSTANCE_TYPE}" ]]; then
      echo "version: v1
sharing:
  timeSlicing:
    resources:
    - name: nvidia.com/gpu
      replicas: 28" > $DIR_PATH/nvidia-device-plugin/config.yaml;
    else
      echo "version: v1
flags:
  migStrategy: mixed
sharing:
  timeSlicing:
    resources:
    - name: nvidia.com/gpu
      replicas: 28
    - name: nvidia.com/$MIG_INSTANCE_TYPE
      replicas: 2" > $DIR_PATH/nvidia-device-plugin/config.yaml;
    fi
    helm upgrade -i nvdp $DIR_PATH/nvidia-device-plugin/nvidia-device-plugin-0.14.2.tgz \
    --namespace nvidia-device-plugin \
    --create-namespace \
    --set runtimeClassName=nvidia \
    -f $DIR_PATH/nvidia-device-plugin/values.yaml;
}
install_cert_manager () {
    echo "installCRDs: true
image:
  repository: quay.io/robolaunchio/cert-manager-controller
  tag: v1.12.4
webhook:
  image:
    repository: quay.io/robolaunchio/cert-manager-webhook
    tag: v1.12.4
cainjector:
  image:
    repository: quay.io/robolaunchio/cert-manager-cainjector
    tag: v1.12.4
startupapicheck:
  enabled: false
  image:
    repository: quay.io/robolaunchio/cert-manager-ctl
    tag: v1.12.4" > $DIR_PATH/cert-manager/values.yaml;
    helm upgrade --install \
      cert-manager $DIR_PATH/cert-manager/cert-manager-v1.12.4.tgz \
      --namespace cert-manager \
      --create-namespace \
      -f $DIR_PATH/cert-manager/values.yaml
    # TODO: Check if cert-manager is up & running.
    sleep 10;
}
create_super_admin_crb () {
        echo "kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: $ORGANIZATION-super-admin-role
rules:
  - apiGroups: ['*']
    resources: ['*']
    verbs: ['*']
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: $ORGANIZATION-super-admin-crb
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: $ORGANIZATION-super-admin-role
subjects:
- kind: Group
  name: $GROUP_SUPER_ADMIN
  apiGroup: rbac.authorization.k8s.io" > crb.yaml;
        kubectl create -f crb.yaml;
        rm -rf crb.yaml;
}
create_admin_crb () {
        echo "kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: $ORGANIZATION-admin-role
rules:
- apiGroups:
  - '*'
  resources:
  - nodes
  - namespaces
  - metricsexporters
  - secrets
  - roles
  - rolebindings
  - pods
  verbs:
  - get
  - list
- apiGroups:
  - '*'
  resources:
  - secrets
  - namespaces
  verbs:
  - create
- apiGroups:
  - '*'
  resources:
  - roles
  - rolebindings
  verbs:
  - create
  - bind
  - escalate
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: $ORGANIZATION-admin-crb
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: $ORGANIZATION-admin-role
subjects:
- kind: Group
  name: $GROUP
  apiGroup: rbac.authorization.k8s.io" > user-crb.yaml;
        kubectl create -f user-crb.yaml;
        rm -rf user-crb.yaml;
}
install_coredns () {
    echo "image:
  repository: quay.io/robolaunchio/coredns
  tag: 1.10.1
service:
  clusterIP: 10.200.2.10
servers:
- zones:
  - zone: .
  port: 53
  plugins:
  - name: errors
  - name: health
    configBlock: |-
      lameduck 5s
  - name: ready
  - name: kubernetes
    parameters: $CLUSTER_DOMAIN.local in-addr.arpa ip6.arpa
    configBlock: |-
      pods insecure
      fallthrough in-addr.arpa ip6.arpa
      ttl 30
  - name: hosts
    parameters: /etc/coredns/NodeHosts
    configBlock: |-
      3.71.45.100     robolaunch-dev-01.robolaunch.internal
      18.184.155.112  aws-robolaunch-server.robolaunch.internal aws-robolaunch-storage.robolaunch.internal aws-robolaunch-backend.robolaunch.internal aws-robolaunch-ui.robolaunch.internal
      ttl 60
      reload 15s
      fallthrough
  - name: prometheus
    parameters: 0.0.0.0:9153
  - name: forward
    parameters: . /etc/resolv.conf
  - name: cache
    parameters: 30
  - name: loop
  - name: reload
  - name: loadbalance" > $DIR_PATH/coredns/values.yaml
        helm upgrade --install \
      coredns $DIR_PATH/coredns/coredns-1.24.5.tgz \
      --namespace coredns \
      --create-namespace \
      -f $DIR_PATH/coredns/values.yaml
        sleep 2;
}
add_host_entries () {
    # [Distributed Setup] add host for control plane
    if [[ -n "${CONTROL_PLANE_HOST_ENTRY}" && $(grep -L "$CONTROL_PLANE_HOST_ENTRY" /etc/hosts) ]]; then
        sed -i "2i$CONTROL_PLANE_HOST_ENTRY" /etc/hosts;
    fi
    # [Distributed Setup] add host for compute plane
    if [[ -n "${COMPUTE_PLANE_HOST_ENTRY}" && $(grep -L "$COMPUTE_PLANE_HOST_ENTRY" /etc/hosts) ]]; then
        sed -i "2i$COMPUTE_PLANE_HOST_ENTRY" /etc/hosts;
    fi
    # [Unified Setup] add host for control & compute plane
    if [[ -n "${CONTROL_COMPUTE_PLANE_HOST_ENTRY}" && $(grep -L "$CONTROL_COMPUTE_PLANE_HOST_ENTRY" /etc/hosts) ]]; then
        sed -i "2i$CONTROL_COMPUTE_PLANE_HOST_ENTRY" /etc/hosts;
    fi
}
install_coredns_as_manifest () {
    COREDNS_SERVICE_CLUSTER_IP="10.200.2.10";
    sed -i "s#<COREDNS-FORWARD>#/etc/resolv.conf#g" $DIR_PATH/coredns/coredns.yaml;
    sed -i "s#<CLOUD-INSTANCE>#$CLOUD_INSTANCE#g" $DIR_PATH/coredns/coredns.yaml;
    sed -i "s#<COREDNS-SERVICE-CLUSTER-IP>#$COREDNS_SERVICE_CLUSTER_IP#g" $DIR_PATH/coredns/coredns.yaml;

    # [Distributed Setup] add host for control plane
    if [[ -z "${CONTROL_PLANE_HOST_ENTRY}" ]]; then
        sed -i '/<CONTROL-PLANE-HOST-ENTRY>/d' $DIR_PATH/coredns/coredns.yaml
    else
        sed -i "s/<CONTROL-PLANE-HOST-ENTRY>/$CONTROL_PLANE_HOST_ENTRY/g" $DIR_PATH/coredns/coredns.yaml;
    fi
    # [Distributed Setup] add host for compute plane
    if [[ -z "${COMPUTE_PLANE_HOST_ENTRY}" ]]; then
        sed -i '/<COMPUTE-PLANE-HOST-ENTRY>/d' $DIR_PATH/coredns/coredns.yaml
    else
        sed -i "s/<COMPUTE-PLANE-HOST-ENTRY>/$COMPUTE_PLANE_HOST_ENTRY/g" $DIR_PATH/coredns/coredns.yaml;
    fi
    # [Unified Setup] add host for control & compute plane
    if [[ -z "${CONTROL_COMPUTE_PLANE_HOST_ENTRY}" ]]; then
        sed -i '/<CONTROL-COMPUTE-PLANE-HOST-ENTRY>/d' $DIR_PATH/coredns/coredns.yaml
    else
        sed -i "s/<CONTROL-COMPUTE-PLANE-HOST-ENTRY>/$CONTROL_COMPUTE_PLANE_HOST_ENTRY/g" $DIR_PATH/coredns/coredns.yaml;
    fi

    echo "apiVersion: v1
kind: ConfigMap
metadata:
  name: host-entries
  namespace: kube-system
data:
  control_plane_host_entry: \"$CONTROL_PLANE_HOST_ENTRY\"
  compute_plane_host_entry: \"$COMPUTE_PLANE_HOST_ENTRY\"
  control_compute_plane_host_entry: \"$CONTROL_COMPUTE_PLANE_HOST_ENTRY\"" > $DIR_PATH/coredns/host-entries-cm.yaml;

    kubectl apply -f $DIR_PATH/coredns/host-entries-cm.yaml;
    kubectl apply -f $DIR_PATH/coredns/coredns.yaml;
}
install_metrics_server () {
    echo "image:
  repository: quay.io/robolaunchio/metrics-server
  tag: v0.6.4" > $DIR_PATH/metrics-server/values.yaml;
    helm upgrade --install \
      metrics-server $DIR_PATH/metrics-server/metrics-server-3.11.0.tgz \
      --namespace metrics-server \
      --create-namespace \
      -f $DIR_PATH/metrics-server/values.yaml;
}
install_ingress_nginx () {
    echo "controller:
  kind: DaemonSet
  hostPort:
    enabled: true
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  ingressClassResource:
    name: nginx
    enabled: true
    default: true
  image:
    registry: quay.io
    image: robolaunchio/ingress-controller
    tag: v1.8.1
    digest: ""
  admissionWebhooks:
    patch:
      image:
        registry: quay.io
        image: robolaunchio/kube-webhook-certgen
        tag: v20230407
        digest: ""
  service:
    type: NodePort
defaultBackend:
  enabled: true
  image:
    registry: quay.io
    image: robolaunchio/defaultbackend-amd64
    tag: 1.5" > $DIR_PATH/ingress-nginx/values.yaml;
        helm upgrade --install \
      ingress-nginx $DIR_PATH/ingress-nginx/ingress-nginx-4.7.1.tgz \
      --namespace ingress-nginx \
      --create-namespace \
      -f $DIR_PATH/ingress-nginx/values.yaml
        sleep 2;
}
install_oauth2_proxy () {
        echo "image:
  repository: quay.io/robolaunchio/oauth2-proxy
  tag: 7.5.0
replicaCount: 1
config:
  clientID: $OIDC_ORGANIZATION_CLIENT_ID
  clientSecret: $OIDC_ORGANIZATION_CLIENT_SECRET
  cookieSecret: $COOKIE_SECRET
  configFile: |-
    provider = 'keycloak-oidc'
    provider_display_name = 'Keycloak'
    oidc_issuer_url = '$OIDC_URL'
    email_domains = ['*']
    scope = 'openid profile email'
    whitelist_domains = '.$DOMAIN'
    cookie_domains= '.$DOMAIN'
    pass_authorization_header = true
    pass_access_token = true
    pass_user_headers = true
    set_authorization_header = true
    set_xauthrequest = true
    cookie_refresh = false
    cookie_expire = '12h'
    redirect_url= 'https://$SERVER_URL/oauth2/callback'
    ssl_insecure_skip_verify = true
    allowed_groups= '$GROUP'" > $DIR_PATH/oauth2-proxy/values.yaml;
        helm upgrade --install \
                oauth2-proxy $DIR_PATH/oauth2-proxy/oauth2-proxy-6.17.0.tgz \
                --namespace oauth2-proxy \
                --create-namespace \
                -f $DIR_PATH/oauth2-proxy/values.yaml;
        sleep 2;
}
install_proxy_ingress () {
        echo "apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth2-proxy
  namespace: oauth2-proxy
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffer-size: '16k'
    nginx.ingress.kubernetes.io/proxy-buffers-number: '4'
spec:
  tls:
  - hosts:
    - $SERVER_URL
    secretName: prod-tls
  rules:
  - host: $SERVER_URL
    http:
      paths:
      - path: /oauth2
        pathType: Prefix
        backend:
          service:
            name: oauth2-proxy
            port:
              number: 80
  ingressClassName: nginx" > proxy-ingress.yaml
    PROXY_INGRESS_INSTALL_SUCCEEDED="false"
    while [ "$PROXY_INGRESS_INSTALL_SUCCEEDED" != "true" ]
    do
        PROXY_INGRESS_INSTALL_SUCCEEDED="true"
                kubectl create -f proxy-ingress.yaml || PROXY_INGRESS_INSTALL_SUCCEEDED="false";
        sleep 1;
    done
        rm -rf proxy-ingress.yaml
}
install_operator_suite () {
    echo "controllerManager:
  kubeRbacProxy:
    image:
      repository: quay.io/robolaunchio/kube-rbac-proxy
      tag: v0.14.0
  manager:
    image:
      repository: quay.io/robolaunchio/robot-controller-manager
      tag: v$ROBOT_OPERATOR_CHART_VERSION" > $DIR_PATH/robot-operator/values.yaml;
    RO_HELM_INSTALL_SUCCEEDED="false"
    while [ "$RO_HELM_INSTALL_SUCCEEDED" != "true" ]
    do
        RO_HELM_INSTALL_SUCCEEDED="true"
        helm upgrade -i \
            robot-operator $DIR_PATH/robot-operator/robot-operator-$ROBOT_OPERATOR_CHART_VERSION.tgz \
            --namespace robot-system \
            --create-namespace \
            --version $ROBOT_OPERATOR_CHART_VERSION \
            -f $DIR_PATH/robot-operator/values.yaml || RO_HELM_INSTALL_SUCCEEDED="false";
        sleep 1;
    done

}
federate_metrics_exporter () {
    wget https://github.com/kubernetes-retired/kubefed/releases/download/v0.9.2/kubefedctl-0.9.2-linux-amd64.tgz;
    tar -xvzf kubefedctl-0.9.2-linux-amd64.tgz;
    mv ./kubefedctl /usr/local/bin/;
    kubefedctl enable namespaces metricsexporters;
}
deploy_metrics_namespace () {
    cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: rl-metrics
EOF
}
install_nvidia_dcgm_exporter () {
    kubectl apply -f https://raw.githubusercontent.com/prometheus-community/helm-charts/main/charts/kube-prometheus-stack/charts/crds/crds/crd-servicemonitors.yaml;
    echo "image:
  repository: nvidia/dcgm-exporter
  tag: 3.3.0-3.2.0-ubuntu22.04
arguments: ["-f", "/etc/dcgm-exporter/dcp-metrics-included.csv"]
serviceMonitor:
  enabled: true
  interval: 3s" > $DIR_PATH/nvidia-dcgm-exporter/values.yaml
    helm upgrade --install \
      dcgm-exporter $DIR_PATH/nvidia-dcgm-exporter/dcgm-exporter-3.2.0.tgz \
      --namespace rl-metrics \
      --create-namespace \
      --set runtimeClassName=nvidia \
      -f $DIR_PATH/nvidia-dcgm-exporter/values.yaml;
}
deploy_metrics_exporter () {
    DEFAULT_NETWORK_INTERFACE=$(route | grep '^default' | grep -o '[^ ]*$')
    cat << EOF | kubectl apply -f -
apiVersion: robot.roboscale.io/v1alpha1
kind: MetricsExporter
metadata:
  name: rl-metrics
  namespace: rl-metrics
  labels:
    robolaunch.io/cloud-instance: $CLOUD_INSTANCE
spec:
  gpu:
    track: true
    interval: 5
  network:
    track: true
    interval: 3
    interfaces:
    - $DEFAULT_NETWORK_INTERFACE
EOF
}
install_metrics_ingress () {
  cat <<EOF > metrics-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rl-metrics
  namespace: rl-metrics
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /\$2
    nginx.ingress.kubernetes.io/proxy-buffer-size: 16k
    nginx.ingress.kubernetes.io/proxy-buffers-number: "4"
spec:
  ingressClassName: nginx
  rules:
    - host: ${SERVER_URL}
      http:
        paths:
          - path: /metrics(/|$)(.*)
            pathType: Prefix
            backend:
              service:
                name: dcgm-exporter
                port:
                  number: 9400
  tls:
    - hosts:
        - ${SERVER_URL}
      secretName: prod-tls
EOF

  kubectl apply -f metrics-ingress.yaml
  rm -f metrics-ingress.yaml
}
set_up_file_manager () {
    FILEBROWSER_CONFIG_PATH=/etc/robolaunch/filebrowser;

    curl -fsSL https://raw.githubusercontent.com/tunahanertekin/filebrowser/master/get.sh | bash;
    mkdir -p /etc/robolaunch/services ${FILEBROWSER_CONFIG_PATH} /var/log/services/vdi;
    git clone https://github.com/robolaunch/file-manager-config ${FILEBROWSER_CONFIG_PATH}/filebrowser-config;

    filebrowser config init -d ${FILEBROWSER_CONFIG_PATH}/filebrowser-host.db;
    filebrowser users add admin admin -d ${FILEBROWSER_CONFIG_PATH}/filebrowser-host.db;
    filebrowser config set --auth.method=noauth -d ${FILEBROWSER_CONFIG_PATH}/filebrowser-host.db;
    filebrowser config set --branding.name "robolaunch" \
        --branding.files ${FILEBROWSER_CONFIG_PATH}"/filebrowser-config/branding" \
        --branding.disableExternal \
        -d ${FILEBROWSER_CONFIG_PATH}/filebrowser-host.db;

    chmod 1777 ${FILEBROWSER_CONFIG_PATH}/filebrowser-host.db /var/log/services ${FILEBROWSER_CONFIG_PATH}/filebrowser-config/;
    chown root ${FILEBROWSER_CONFIG_PATH}/filebrowser-host.db /var/log/services ${FILEBROWSER_CONFIG_PATH}/filebrowser-config/;

    echo "[Unit]
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser -b /host -a 127.0.0.1 -p 2500 -d /etc/robolaunch/filebrowser/filebrowser-host.db -r /

[Install]
WantedBy=default.target" > /etc/systemd/system/filebrowser.service;
    chmod 664 /etc/systemd/system/filebrowser.service;
    systemctl daemon-reload;
    systemctl enable filebrowser.service;
    systemctl start filebrowser.service;

    # deploy kubernetes resources for filebrowser relay
    sed -i "s/<CLOUD-INSTANCE>/$CLOUD_INSTANCE/g" $DIR_PATH/filemanager/filebrowser-relay-resources.yaml;
    sed -i "s/<ROOT-DNS>/$DOMAIN/g" $DIR_PATH/filemanager/filebrowser-relay-resources.yaml;
    kubectl apply -f $DIR_PATH/filemanager/filebrowser-relay-resources.yaml;
}

##############################################################
##############################################################
##############################################################

print_global_log "Waiting for the preflight checks...";
(check_if_root)
(check_firewall)
print_global_log "Waiting for the apt database lock...";
(wait_for_apt_db_lock)
print_global_log "Configuring remote SSH connection...";
(configuring_ssh)
(install_pre_tools)
(get_versioning_map)
(make_life_more_beautiful)
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
print_global_log "Creating directories...";
(create_directories)
print_global_log "Installing tools...";
(install_post_tools)
print_global_log "Setting up NVIDIA container runtime...";
(set_up_nvidia_container_runtime)
print_global_log "Copying Start Script...";
(copy_start_script)
print_global_log "Adding host entries...";
(add_host_entries)
print_global_log "Setting up k3s cluster...";
(set_up_k3s)
print_global_log "Checking cluster health...";
(check_cluster)
print_global_log "Labeling node...";
(label_node)
print_global_log "Creating admin crb...";
(create_admin_crb)
print_global_log "Creating super admin crb...";
(create_super_admin_crb)
# print_global_log "Installing coredns...";
# (install_coredns)
print_global_log "Installing coredns...";
(install_coredns_as_manifest)
print_global_log "Installing metrics-server...";
(install_metrics_server)
print_global_log "Installing ingress...";
(install_ingress_nginx)
print_global_log "Installing oauth2-proxy...";
(install_oauth2_proxy)
print_global_log "Installing openebs...";
(install_openebs)
print_global_log "Installing cert-manager...";
(install_cert_manager)
print_global_log "Installing proxy-ingress...";
(install_proxy_ingress)
print_global_log "Installing NVIDIA runtime...";
(install_nvidia_runtime_class)
print_global_log "Installing NVIDIA device plugin...";
(install_nvidia_device_plugin)
#print_global_log "Installing robolaunch Operator Suite...";
#(install_operator_suite)
print_global_log "Deploying MetricsExporter namespace...";
(deploy_metrics_namespace)
print_global_log "Installing NVIDIA DCGM exporter...";
(install_nvidia_dcgm_exporter)
#print_global_log "Deploying MetricsExporter...";
#(deploy_metrics_exporter)
print_global_log "Deploying Metrics Ingress...";
(install_metrics_ingress)
#print_global_log "Setting up file manager...";
#(set_up_file_manager)
