# HackingKubernetes  
This repository contain any information that can be used to hack Kubernetes.

# Offensive  
## Atricles  
[Securing Kubernetes Clusters by Eliminating Risky Permissions](https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/)  
[Kubernetes Pentest Methodology Part 1](https://www.cyberark.com/he/threat-research-blog/kubernetes-pentest-methodology-part-1/)  
[Kubernetes Pentest Methodology Part 2](https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-2/)  
[Kubernetes Pentest Methodology Part 3](https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-3/)  
[Eight Ways to Create a Pod](https://www.cyberark.com/threat-research-blog/eight-ways-to-create-a-pod/)  
[Leaked Code from Docker Registries](https://unit42.paloaltonetworks.com/leaked-docker-code/)  
[Kubernetes Pod Escape Using Log Mounts](https://blog.aquasec.com/kubernetes-security-pod-escape-log-mounts)  


### kubelet
[https://faun.pub/attacking-kubernetes-clusters-using-the-kubelet-api-abafc36126ca](https://faun.pub/attacking-kubernetes-clusters-using-the-kubelet-api-abafc36126ca)  
[https://rhinosecuritylabs.com/cloud-security/kubelet-tls-bootstrap-privilege-escalation/](https://rhinosecuritylabs.com/cloud-security/kubelet-tls-bootstrap-privilege-escalation/)  

### Containers and Pods   
[Bad Pods: Kubernetes Pod Privilege Escalation](https://labs.bishopfox.com/tech-blog/bad-pods-kubernetes-pod-privilege-escalation)   
[Risk8s Business: Risk Analysis of Kubernetes Clusters](https://tldrsec.com/guides/kubernetes/)   
[CVE-2020-15157 "ContainerDrip" Write-up](https://darkbit.io/blog/cve-2020-15157-containerdrip)   
[Deep Dive into Real-World Kubernetes Threats](https://research.nccgroup.com/2020/02/12/command-and-kubectl-talk-follow-up/)   
[Unpatched Docker bug allows read-write access to host OS](https://nakedsecurity.sophos.com/2019/05/31/unpatched-docker-bug-allows-read-write-access-to-host-os/)  
[Docker Container Breakout: Abusing SYS_MODULE capability!](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd)   
[Container Breakouts – Part 1: Access to root directory of the Host](https://blog.nody.cc/posts/container-breakouts-part1/)   
[Privileged Container Escapes with Kernel Modules](https://xcellerator.github.io/posts/docker_escape/)   
[Digging into cgroups Escape](https://0xdf.gitlab.io/2021/05/17/digging-into-cgroups.html)  
[Understanding Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)  

## PDF  
[Abusing Privileged and Unprivileged Linux
Containers ](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)  
[Defending Containers](https://www.intezer.com/wp-content/uploads/2021/03/Intezer-Defending-Containers.pdf)   

## Videos    
[Compromising Kubernetes Cluster by Exploiting RBAC Permissions](https://www.youtube.com/watch?v=1LMo0CftVC4)   
[How We Used Kubernetes to Host a Capture the Flag (CTF) - Ariel Zelivansky & Liron Levin, Twistlock](https://www.youtube.com/watch?v=kUmaKvxdfvg) ([presentation](https://static.sched.com/hosted_files/kccnceu19/6b/kubecon%20talk.pdf))  
[Crafty Requests: Deep Dive Into Kubernetes CVE-2018-1002105 - Ian Coldwater, Heroku](https://www.youtube.com/watch?v=VjSJqc13PNk) ([presentation](https://static.sched.com/hosted_files/kccnceu19/a5/craftyrequests.pdf))
[A Hacker's Guide to Kubernetes and the Cloud - Rory McCune, NCC Group PLC (Intermediate Skill Level)](https://www.youtube.com/watch?v=dxKpCO2dAy8)    
[Advanced Persistence Threats: The Future of Kubernetes Attacks](https://www.youtube.com/watch?v=CH7S5rE3j8w)  
[Hack my mis-configured Kubernetes - Or Kamara](https://www.youtube.com/watch?v=XNPDtNbcPr4)  
[LISA19 - Deep Dive into Kubernetes Internals for Builders and Operators](https://www.youtube.com/watch?v=3KtEAa7_duA)  
[DIY Pen-Testing for Your Kubernetes Cluster - Liz Rice, Aqua Security](https://www.youtube.com/watch?v=fVqCAUJiIn0)  
[Hacking and Hardening Kubernetes Clusters by Example](https://www.youtube.com/watch?v=vTgQLzeBfRU)  
[Tutorial: Attacking and Defending Kube...](https://www.youtube.com/watch?v=UdMFTdeAL1s)  
[Securing (and pentesting) the great spaghetti monster (k8s)](https://www.youtube.com/watch?v=VjGEk-F46bs)  
[Jay Beale - Kubernetes Practical Attack and Defense](https://www.youtube.com/watch?v=LtCx3zZpOfs)    
[Jay Beale - Quick Intro Attacking a Kubernetes Cluster](https://www.youtube.com/watch?v=fZJ-5rAwcp0)  
[Jay Beale - Attacking and Defending Kubernetes - DEF CON 27 Packet Hacking Village](https://www.youtube.com/watch?v=2fmAuR3rnBo)  
[Jay Beale - Kubernetes Attack and Defense: Inception-Style](https://www.youtube.com/watch?v=cCyDAJHkNO4)  
[Jay Beale - RSA20219: Hacking and Hardening Kubernetes](https://www.youtube.com/watch?v=wlgAWSbY0gI)  
[Attacking Kubernetes Clusters Through Your Network Plumbing](https://www.youtube.com/watch?v=gX1WXyM4IIQ)  
[Magno Logan - TrendMicro: Kubernetes Security - Attacking and Defending K8s Clusters](https://www.youtube.com/watch?v=pl2WVPP4-Zw)  
[Magno Logan - CloudSecNextSummit2021: Kubernetes Security - Attacking and Defending K8s Clusters](https://www.youtube.com/watch?v=Ek1oaGwfli0)   
[Magno Logan - Hackfest HF: Kubernetes Security: Attacking and Defending K8s Clusters](https://www.youtube.com/watch?v=ROiCGwVV_zU)  

## Vulnerabilities
### 2020  
[Protecting Against an Unfixed Kubernetes Man-in-the-Middle Vulnerability (CVE-2020-8554)](https://unit42.paloaltonetworks.com/cve-2020-8554/)    
[Kubernetes Vulnerability Puts Clusters at Risk of Takeover (CVE-2020-8558)](https://unit42.paloaltonetworks.com/cve-2020-8558/)   
  
  
### 2019

[Top 5 Kubernetes Vulnerabilities of 2019 - the Year in Review](https://www.stackrox.com/post/2020/01/top-5-kubernetes-vulnerabilities-of-2019-the-year-in-review/)   

#### Kubectl vulnerability (CVE-2019-1002101)
[Disclosing a directory traversal vulnerability in Kubernetes copy – CVE-2019-1002101](https://unit42.paloaltonetworks.com/disclosing-directory-traversal-vulnerability-kubernetes-copy-cve-2019-1002101/)  

#### Kubernetes API server vulnerability (CVE-2019-11247)
[Kubernetes API server vulnerability (CVE-2019-11247)](https://www.stackrox.com/post/2019/08/how-to-remediate-kubernetes-security-vulnerability-cve-2019-11247/)  

#### Kubernetes billion laughs attack vulnerability (CVE-2019-11253)

[CVE-2019-11253: Kubernetes API Server JSON/YAML parsing vulnerable to resource exhaustion attack](https://github.com/kubernetes/kubernetes/issues/83253)  

### 2018

[Demystifying Kubernetes CVE-2018-1002105 (and a dead simple exploit)](https://unit42.paloaltonetworks.com/demystifying-kubernetes-cve-2018-1002105-dead-simple-exploit/)  
[https://sysdig.com/blog/privilege-escalation-kubernetes-dashboard/](CVE-2018-18264 Privilege escalation through Kubernetes dashboard.)  

## Tools  
[kubesploit](https://github.com/cyberark/kubesploit)  
[kubiscan](https://github.com/cyberark/KubiScan)  
[kubeletctl](https://github.com/cyberark/kubeletctl)   
[kube-hunter](https://github.com/aquasecurity/kube-hunter)  

# Defensive  
[Smarter Kubernetes Access Control: A Simpler Approach to Auth - Rob Scott, ReactiveOps](https://www.youtube.com/watch?v=egQnymnZ9eg)  


# Others
## Install Docker on Ubuntu
Reference from [here](https://docs.docker.com/engine/install/ubuntu/#installation-methods).  
```
# remove old versions
apt-get remove docker docker-engine docker.io containerd runc
# install
apt-get update
apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install docker-ce docker-ce-cli containerd.io

```

## Install minikube  
The documentation can be found [here](https://minikube.sigs.k8s.io/docs/start/). In AWS you need to run:  
```
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
install minikube-linux-amd64 /usr/local/bin/minikube
swapoff -a
apt install conntrack
minikube start --driver=none
```  

## Install kubectl  
```
# https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

## Create containers
### Privileged container
```
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
  - name: sec-ctx-8
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      allowPrivilegeEscalation: true
      privileged: true
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        add: ["NET_ADMIN", "SYS_TIME"]
EOF
```

### Container with environment variables passwords

```
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: envvars-db
  namespace: default
spec:
  containers:
  - name: envvars-multiple-secrets
    image: nginx
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          key: db-username-key
          name: db-username
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          key: db-password-key
          name: db-password
EOF

```


```
kubectl apply -f - <<EOF

apiVersion: v1
kind: Namespace
metadata:
  creationTimestamp: null
  name: mars
---

apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: mars
  name: user1
  
---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: kube-system
  name: list-secrets
rules:
- apiGroups: ["*"]
  resources: ["secrets"]
  verbs: ["get", "list"]
  
---

apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  namespace: kube-system
  name: list-secrets-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: list-secrets
subjects:
  - kind: ServiceAccount
    name: user1
    namespace: mars
    
---

apiVersion: v1
kind: Pod
metadata:
  name: alpine-secret
  namespace: mars
spec:
  containers:
  - name: alpine-secret
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 100000"]
  serviceAccountName: user1
  automountServiceAccountToken: true
  hostNetwork: true
---

apiVersion: v1
kind: Secret
metadata:
  name: db-username
data:
  db-username-key: YWRtaW4=

---

apiVersion: v1
kind: Secret
metadata:
  name: db-password
data:
  db-password-key: MTIzNDU=

EOF

```

## Get ServiceAccount token by name
```
kubectl get secrets $(kubectl get sa <SERVICE_ACCOUNT_NAME> -o json | jq -r '.secrets[].name') -o json | jq -r '.data.token' | base64 -d
```

Function:
```
alias k=kubectl
function getSecretByName {
k get secrets $(k get sa $1 -o json | jq -r '.secrets[].name') -o json | jq -r '.data.token' | base64 -d
}

getSecretByName <serviceAccountName>
```

*Replace `<SERVICE_ACCOUNT_NAME>` with the name

## Delete multiple containers
```
// delete by match with grep
kubectl delete po $(kubectl get pods -o go-template -n <NAMESPACE> --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' | grep <SEARCH_STRING) -n <NAMESPACE>

// delete specific pods
kubectl delete pods -n <NAMESPACE> $(echo -e 'alpine1\nalpine2\nalpine3')
```

## Get docker container IPs
```
docker inspect --format='{{.Name}}' $(docker ps -aq -f label=kubelabel)
docker inspect --format='{{ .NetworkSettings.IPAddress }}' $(docker ps -aq -f label=kubelabel)
```
