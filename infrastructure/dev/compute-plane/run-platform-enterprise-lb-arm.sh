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
OIDC_URL=https://$identity_subdomain.$root_domain/realms/$default_realm
OIDC_ORGANIZATION_CLIENT_ID=operator-client
OIDC_ORGANIZATION_CLIENT_SECRET=$org_client_secret
COOKIE_SECRET=MFlZN1J5eitIdUplckJLaW55YlF6UjVlQ3lneFJBcEU=
DOMAIN=$root_domain
SERVER_URL=$CLOUD_INSTANCE.$DOMAIN
GITHUB_PATH=$github_pat
NVIDIA_DRIVER_VERSION="580" # $nvidia_driver_version
CUSTOM_HOSTNAME=$custom_hostname
CLOUD_PROVIDER=$cloud_provider

if [ "$CLOUD_PROVIDER" != "default" ]; then
    GROUP_SUPER_ADMIN=org_$CLOUD_PROVIDER"_super_admin"
	GROUP=org_$org_name_plain
fi

if [ -n "$CUSTOM_HOSTNAME" ]; then
    SERVER_URL="$CUSTOM_HOSTNAME"
else
    SERVER_URL="$CLOUD_INSTANCE.$DOMAIN"
fi

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
	mkdir -p $DIR_PATH/gpu-operator;
    mkdir -p $DIR_PATH/nvidia-dcgm-exporter;
    mkdir -p $DIR_PATH/ingress-nginx;
    mkdir -p $DIR_PATH/oauth2-proxy;
    mkdir -p $DIR_PATH/robot-operator;
    mkdir -p $DIR_PATH/filemanager;

    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/coredns https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/coredns-1.24.5.tgz
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/coredns https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/coredns.yaml
    wget --header "Authorization: token $GITHUB_PAT" -P $DIR_PATH/metrics-server https://github.com/robolaunch/on-premise/releases/download/$PLATFORM_VERSION/metrics-server-3.11.0.tgz
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
	curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo apt-key add -
    echo "deb https://nvidia.github.io/libnvidia-container/stable/deb/arm64 /" | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
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
	  --tls-san=$SERVER_URL \
          --cluster-domain=$CLUSTER_DOMAIN.local \
          --disable-network-policy \
          --disable=traefik \
          --disable=local-storage \
		  --data-dir=/data/lib/ \
          --pause-image=quay.io/robolaunchio/mirrored-pause:3.6 \
          --kube-apiserver-arg \
            oidc-issuer-url=$OIDC_URL \
          --kube-apiserver-arg \
            oidc-client-id=$OIDC_ORGANIZATION_CLIENT_ID \
          --kube-apiserver-arg \
            oidc-username-claim=preferred_username \
          --kube-apiserver-arg \
            oidc-groups-claim=groups \
		  --kubelet-arg \
		    runtime-request-timeout=3h \
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
    echo "openebs-crds:
  csi:
    volumeSnapshots:
      enabled: false
      keep: false
localpv-provisioner:
  enabled: true
  rbac:
    create: true
# Disable everything else
zfs-localpv:
  enabled: false
lvm-localpv:
  enabled: false
rawfile-localpv:
  enabled: false
mayastor:
  enabled: false
loki:
  enabled: false
alloy:
  enabled: false
preUpgradeHook:
  enabled: false
engines:
  local:
    lvm:
      enabled: false
    zfs:
      enabled: false
    rawfile:
      enabled: false
  replicated:
    mayastor:
      enabled: false" > $DIR_PATH/openebs/values.yaml;
    helm repo add openebs https://openebs.github.io/openebs
    helm repo update
    kubectl create namespace openebs
    helm install openebs openebs/openebs \
      --namespace openebs \
      --version 4.3.2 \
      -f $DIR_PATH/openebs/values.yaml
    sleep 5;
    kubectl patch storageclass openebs-hostpath -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}';
    kubectl patch storageclass openebs-hostpath --type merge -p '{"metadata": {"annotations": {"cas.openebs.io/config": "- name: StorageType\n  value: \"hostpath\"\n- name: BasePath\n  value: \"/data/openebs/local\"","openebs.io/cas-type": "local"}}}'
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
  kind: Deployment
  replicaCount: 1
  allowSnippetAnnotations: true
  config:
    annotations-risk-level: Critical
  ingressClassResource:
    name: nginx
    enabled: true
    default: true
  service:
    type: NodePort
    nodePorts:
      http: 32080
      https: 32443
defaultBackend:
  enabled: true" > $DIR_PATH/ingress-nginx/values.yaml;
     helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
     helm repo update
     helm install ingress-nginx ingress-nginx/ingress-nginx \
           --namespace ingress-nginx \
           --create-namespace \
           --version 4.12.6 \
           -f $DIR_PATH/ingress-nginx/values.yaml
     sleep 2;
}
install_oauth2_proxy () {
        echo "replicaCount: 1
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
    allowed_groups = ['${GROUP}', 'org_${CLOUD_PROVIDER}_super_admin']
    oidc_groups_claim = 'groups'" > $DIR_PATH/oauth2-proxy/values.yaml;
	    helm repo add oauth2-proxy https://oauth2-proxy.github.io/manifests
		
        helm upgrade --install \
                oauth2-proxy oauth2-proxy/oauth2-proxy \
                --namespace oauth2-proxy \
                --create-namespace \
                --version 8.2.2 \
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

# ---- GPU Operator Config Function ----
configure_gpu_operator() {
  local gpu_count=${GPU_COUNT:-1}        # toplam GPU sayısı (default 1)
  local ts_replicas=${TS_REPLICAS:-4}    # time-slicing replicas
  local HELM_VERSION=${HELM_VERSION:-"v25.3.4"}   # helm chart versiyonu

  MIG_CONFIG_FILE="$DIR_PATH/gpu-operator/mig-configmap.yaml"
  TS_CONFIG_FILE="$DIR_PATH/gpu-operator/ts-configmap.yaml"
  VALUES_FILE="$DIR_PATH/gpu-operator/values.yaml"

  # --- Helm repo ve namespace setup ---
  helm repo add nvidia https://nvidia.github.io/gpu-operator || true
  helm repo update
  kubectl create ns gpu-operator || true

  # --- Node name otomatik seç (tek node varsayımı) ---
  if [[ -z "${NODE_NAME:-}" ]]; then
    NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
    echo "ℹ️  NODE_NAME belirtilmedi, otomatik olarak seçildi: ${NODE_NAME}"
  fi

  # MIG config başlat (all-disabled her zaman var)
  cat > ${MIG_CONFIG_FILE} <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: custom-mig-config
  namespace: gpu-operator
data:
  config.yaml: |-
    version: v1
    mig-configs:
      all-disabled:
        - devices: all
          mig-enabled: false
      custom-mig:
EOF

  local mig_used=false
  local ts_used=false

  for ((i=0; i<gpu_count; i++)); do
    mode_var="GPU${i}_MODE"
    mode=${!mode_var:-bare}   # default bare

    case "$mode" in
      mig)
        mig_used=true
        profiles_var="GPU${i}_MIG_PROFILES"
        profiles=${!profiles_var:-}
        if [[ -n "$profiles" ]]; then
          echo "        - devices: [${i}]" >> ${MIG_CONFIG_FILE}
          echo "          mig-enabled: true" >> ${MIG_CONFIG_FILE}
          echo "          mig-devices:" >> ${MIG_CONFIG_FILE}
          IFS=',' read -ra items <<< "$profiles"
          for item in "${items[@]}"; do
            profile=$(echo $item | cut -d: -f1)
            count=$(echo $item | cut -d: -f2)
            echo "            \"${profile}\": ${count}" >> ${MIG_CONFIG_FILE}
          done
        else
          echo "        - devices: [${i}]" >> ${MIG_CONFIG_FILE}
          echo "          mig-enabled: true" >> ${MIG_CONFIG_FILE}
        fi
        ;;
      ts)
        ts_used=true
        echo "        - devices: [${i}]" >> ${MIG_CONFIG_FILE}
        echo "          mig-enabled: false" >> ${MIG_CONFIG_FILE}
        ;;
      bare)
        echo "        - devices: [${i}]" >> ${MIG_CONFIG_FILE}
        echo "          mig-enabled: false" >> ${MIG_CONFIG_FILE}
        ;;
      *)
        echo "⚠️  Geçersiz mod: $mode (GPU${i})"
        ;;
    esac
  done

  # Time-slicing ConfigMap 
  if [[ "$ts_used" == true ]]; then
    cat > ${TS_CONFIG_FILE} <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: device-plugin-config
  namespace: gpu-operator
data:
  config.yaml: |-
    version: v1
    sharing:
      timeSlicing:
        resources:
          - name: nvidia.com/gpu
            replicas: ${ts_replicas}
EOF
    kubectl apply -f ${TS_CONFIG_FILE}
  fi

  # MIG ConfigMap 
  if [[ "$mig_used" == true ]]; then
    kubectl apply -f ${MIG_CONFIG_FILE}
    kubectl label node ${NODE_NAME} nvidia.com/mig.config=custom-mig --overwrite
  fi

  # values.yaml 
  cat > ${VALUES_FILE} <<EOF
mig:
  strategy: mixed
EOF

  if [[ "$ts_used" == true && "$mig_used" == true ]]; then
    # MIG + TS 
    cat >> ${VALUES_FILE} <<EOF
devicePlugin:
  enabled: true
  runtimeClassName: nvidia
  config:
    name: device-plugin-config
    default: config.yaml
    create: false
migManager:
  enabled: true
  runtimeClassName: nvidia
  config:
    name: custom-mig-config
    default: ""
toolkit:
  enabled: false
EOF

  elif [[ "$ts_used" == true ]]; then
    # Sadece TS
    cat >> ${VALUES_FILE} <<EOF
devicePlugin:
  enabled: true
  runtimeClassName: nvidia
  config:
    name: device-plugin-config
    default: config.yaml
    create: false
migManager:
  enabled: false
toolkit:
  enabled: false
EOF

  elif [[ "$mig_used" == true ]]; then
    # Sadece MIG
    cat >> ${VALUES_FILE} <<EOF
devicePlugin:
  enabled: true
  runtimeClassName: nvidia
migManager:
  enabled: true
  runtimeClassName: nvidia
  config:
    name: custom-mig-config
    default: ""
toolkit:
  enabled: false
EOF

  else
    # No MIG no TS
    cat >> ${VALUES_FILE} <<EOF
devicePlugin:
  enabled: true
  runtimeClassName: nvidia
migManager:
  enabled: false
toolkit:
  enabled: false
EOF
  fi

  # Deploy GPU Operator
  helm upgrade --install gpu-operator nvidia/gpu-operator \
    -n gpu-operator \
    --create-namespace \
    -f ${VALUES_FILE} \
    --version=${HELM_VERSION}
}

install_monitoring_stack () {
    print_log "🚀 Installing Kube-Prometheus-Stack (Prometheus + Grafana)..."

    local NAMESPACE="monitoring"
    local CHART_VERSION="77.14.0"
    local VALUES_FILE="$DIR_PATH/gpu-operator/values-monitoring.yaml"

    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts || true
    helm repo update

    # --- Dynamic Helm values file ---
    cat > $VALUES_FILE <<EOF
grafana:
  enabled: false

alertmanager:
  enabled: false

prometheus:
  ingress:
    enabled: true
    ingressClassName: nginx
    annotations:
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    hosts:
      - ${SERVER_URL}
    paths:
      - /prometheus
    pathType: Prefix
    tls:
      - secretName: prod-tls
        hosts:
          - ${SERVER_URL}

  service:
    type: ClusterIP

  additionalServiceMonitors:
    - name: nvidia-dcgm-exporter
      selector:
        matchLabels:
          app: nvidia-dcgm-exporter
      namespaceSelector:
        matchNames:
          - gpu-operator
      endpoints:
        - port: gpu-metrics
          interval: 30s

  prometheusSpec:
    externalUrl: https://${SERVER_URL}/prometheus/
    routePrefix: /prometheus
    scrapeInterval: 15s
    evaluationInterval: 30s
    retention: 7d
    retentionSize: "40GiB"
    walCompression: true
    storageSpec:
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 50Gi
    podMonitorSelectorNilUsesHelmValues: false
    ruleSelectorNilUsesHelmValues: false

prometheusOperator:
  enabled: true

nodeExporter:
  enabled: true
kubelet:
  enabled: true
coreDns:
  enabled: true
kubeStateMetrics:
  enabled: true
kubeControllerManager:
  enabled: true
kubeScheduler:
  enabled: true
kubeProxy:
  enabled: true
EOF

    # --- Helm install (retry safe) ---
    helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
      -n $NAMESPACE \
      --create-namespace \
      --version $CHART_VERSION \
      -f $VALUES_FILE

    print_log "✅ Kube-Prometheus-Stack installed successfully in namespace $NAMESPACE."

    # --- Wait for Operator pod ---
    print_log "⏳ Waiting for Prometheus Operator pod to become Ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=prometheus-operator -n $NAMESPACE --timeout=180s || print_err "❌ Operator pod not ready."

    # --- Wait for Prometheus pod ---
    print_log "⏳ Waiting for Prometheus pod to become Ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=prometheus -n $NAMESPACE --timeout=180s || print_err "❌ Prometheus pod not ready."
    
	rm -f $VALUES_FILE
}


prepare_offline_packages () {
    print_log "Preparing local offline packages for code-server, JupyterLab, ttyd, and FileBrowser..."

    local BASE_DIR="/data/robolaunch/offline-packages"
    local CODE_VERSION="4.104.2"    # https://github.com/coder/code-server/releases
    local TTYD_VERSION="1.7.7"      # https://github.com/tsl0922/ttyd/releases
    local FB_VERSION="v2.44.0"      # https://github.com/filebrowser/filebrowser/releases

    mkdir -p ${BASE_DIR}/{code-server,jupyter,ttyd,filebrowser}

    # --- CODE-SERVER ---
    print_log "📦 Downloading code-server ${CODE_VERSION}..."
    cd ${BASE_DIR}/code-server
    wget -q https://github.com/coder/code-server/releases/download/v${CODE_VERSION}/code-server-${CODE_VERSION}-linux-arm64.tar.gz
	tar -xzf code-server-${CODE_VERSION}-linux-arm64.tar.gz
	#mv code-server-${CODE_VERSION}-linux-arm64/bin/code-server .
	mv code-server-${CODE_VERSION}-linux-arm64 latest
	#rm -rf code-server-${CODE_VERSION}-linux-arm64*
	rm -f code-server-${CODE_VERSION}-linux-arm64.tar.gz
	chmod +x latest/bin/code-server
	#chmod +x code-server

    # --- JUPYTER ---
    print_log "📦 Downloading JupyterLab dependencies..."
    cd ${BASE_DIR}/jupyter
    apt-get update -y >/dev/null 2>&1
    apt-get install -y python3-pip >/dev/null 2>&1
    pip download jupyterlab==4.4.8 -d .

    # --- TTYD ---
    print_log "📦 Downloading ttyd ${TTYD_VERSION}..."
    cd ${BASE_DIR}/ttyd
    wget -q https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/ttyd.aarch64 -O ttyd
    chmod +x ttyd

    # --- FILEBROWSER ---
    print_log "📦 Downloading FileBrowser ${FB_VERSION}..."
    cd ${BASE_DIR}/filebrowser
    wget -q https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/linux-arm64-filebrowser.tar.gz
    tar -xzf linux-arm64-filebrowser.tar.gz
    rm -f linux-arm64-filebrowser.tar.gz

    print_log "✅ Offline packages are ready under ${BASE_DIR}."
}

apply_nvidia_dcgm_servicemonitor () {
    print_log "📡 Applying ServiceMonitor for NVIDIA DCGM Exporter..."

    # ServiceMonitor CRD mevcut mu kontrol et
    if ! kubectl get crd servicemonitors.monitoring.coreos.com &>/dev/null; then
        print_err "❌ ServiceMonitor CRD not found. Prometheus Operator may not be installed yet."
        return 1
    fi

    # YAML oluştur ve uygula
    cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: nvidia-dcgm-exporter
  namespace: monitoring
  labels:
    release: kube-prometheus-stack
    app.kubernetes.io/instance: kube-prometheus-stack
spec:
  selector:
    matchLabels:
      app: nvidia-dcgm-exporter
  namespaceSelector:
    matchNames: [ gpu-operator ]
  endpoints:
    - port: gpu-metrics
      interval: 30s
EOF

    # Doğrulama
    print_log "🔍 Verifying ServiceMonitor existence..."
    if kubectl get servicemonitor nvidia-dcgm-exporter -n monitoring &>/dev/null; then
        print_log "✅ ServiceMonitor 'nvidia-dcgm-exporter' successfully applied and active."
    else
        print_err "❌ Failed to create ServiceMonitor 'nvidia-dcgm-exporter'."
    fi
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
#print_global_log "Installing coredns...";
#(install_coredns_as_manifest)
#print_global_log "Installing metrics-server...";
#(install_metrics_server)
print_global_log "Installing ingress...";
(install_ingress_nginx)
print_global_log "Installing oauth2-proxy...";
(install_oauth2_proxy)
print_global_log "Installing openebs...";
(install_openebs)
print_global_log "Installing proxy-ingress...";
(install_proxy_ingress)
print_global_log "Installing NVIDIA runtime...";
(install_nvidia_runtime_class)
print_global_log "Installing NVIDIA gpu operator...";
(configure_gpu_operator)
print_global_log "Installing Monitoring Stack..."
(install_monitoring_stack)
print_global_log "Preparing offline packages..."
(prepare_offline_packages)
print_global_log "Applying service monitor..."
(apply_nvidia_dcgm_servicemonitor)
