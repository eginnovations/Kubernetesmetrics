package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var kubeconfig string
	var crdconfigPath string
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "kubeconfig",
				Aliases: []string{"c"},
				Usage:   "Load kubeconfiguration from `FILE`",
			},
			&cli.StringFlag{
				Name:    "crdconfig",
				Aliases: []string{"crd"},
				Usage:   "Load crd configuration from `FILE`",
			},
		},
		Action: func(c *cli.Context) error {
			kubeconfig = c.String("kubeconfig")
			crdconfigPath = c.String("crdconfig")
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

	if crdconfigPath == "" || kubeconfig == "" {
		log.Fatalf("kubeconfig or config file missing")
	}

	crdconfig, err := os.ReadFile(crdconfigPath)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}

	var containerConfig Config
	err = yaml.Unmarshal(crdconfig, &containerConfig)
	if err != nil {
		log.Fatalf("error unmarshalling YAML: %v", err)
	}

	// Validate required fields
	if containerConfig.Apiversion == "" {
		log.Fatalf("Missing required field: apiVersion")
	}
	if containerConfig.Kind == "" {
		log.Fatalf("Missing required field: kind")
	}
	if containerConfig.Metadata.Name == "" {
		log.Fatalf("Missing required field: metadata.name")
	}
	if containerConfig.Metadata.Namespace == "" {
		log.Fatalf("Missing required field: metadata.namespace")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Failed to build kubeconfig: %v", err)
	}

	kubeClientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	metricsErr := getKubeMetrics(kubeClientset, &containerConfig)
	if metricsErr != nil {
		log.Printf("Error fetching metrics: %v", metricsErr)
	}
}

func getKubeMetrics(kubeClientset *kubernetes.Clientset, containerConfig *Config) error {
	apiDiscoveryClient := kubeClientset.Discovery()
	apiGroups, err := apiDiscoveryClient.ServerGroups()
	if err != nil {
		panic(err)
	}

	cluster := ""
	apiGroupToFind := "route.openshift.io"
	for _, group := range apiGroups.Groups {
		if group.Name == apiGroupToFind {
			cluster = "openshift"
		}
	}
	fmt.Println(cluster)
	deployments, _ := kubeClientset.AppsV1().Deployments(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	daemons, _ := kubeClientset.AppsV1().DaemonSets(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	replicas, _ := kubeClientset.AppsV1().ReplicaSets(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})

	pods, _ := kubeClientset.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	nodes, _ := kubeClientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	namespaces, _ := kubeClientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	services, _ := kubeClientset.CoreV1().Services(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})

	var metrics Metrics

	metrics.NodeTotal = len(nodes.Items)
	metrics.PodsTotal = len(pods.Items)
	for _, item := range nodes.Items {
		var nodes NodeMetrics
		nodes.Name = item.Name
		nodes.NodeAddress = item.Status.Addresses[0].Address
		nodes.KernelVersion = item.Status.NodeInfo.KernelVersion
		nodes.OsImage = item.Status.NodeInfo.OSImage
		nodes.ContainerRuntimeVersion = item.Status.NodeInfo.ContainerRuntimeVersion
		nodes.KubeletVersion = item.Status.NodeInfo.KubeletVersion
		nodes.PodCIDR = item.Spec.PodCIDR
		nodes.SystemUUID = item.Status.NodeInfo.SystemUUID
		nodes.InternalIP = item.Status.Addresses[0].Address
		nodes.CapacityCPU = item.Status.Capacity.Cpu().String()
		nodes.CapacityPods = item.Status.Capacity.Pods().String()
		nodes.CapacityEphemeralStorage = item.Status.Capacity.StorageEphemeral().String()
		nodes.CapacityMemory = item.Status.Capacity.Memory().String()
		nodes.CreatedTimestamp = item.CreationTimestamp.Time
		nodes.AllocatableCPU = item.Status.Allocatable.Cpu().String()
		nodes.AllocatableMemory = item.Status.Allocatable.Memory().String()
		nodes.AllocatablePods = item.Status.Allocatable.Pods().String()
		metrics.NodeInfo = append(metrics.NodeInfo, nodes)
	}
	var matchNameSpaces []string
	var labelsMap []Labels
	var selectedContainer string
	if containerConfig.Spec.Features.APM.Enabled {
		matchNameSpaces = containerConfig.Spec.Features.APM.MonitoredNamespaces
		labelsMap = containerConfig.Spec.Features.APM.Java.LabelsToMatch
	}

	for _, item := range namespaces.Items {

		var namespace NamespaceMetric
		namespace.Name = item.Name
		namespace.UID = string(item.UID)
		namespace.CreatedTimestamp = item.CreationTimestamp.Time
		namespace.StatusPhase = string(item.Status.Phase)
		namespaceLabel := item.Labels["kubernetes.io/metadata.name"]

		for _, pat := range matchNameSpaces {
			result := matchWildcard(namespaceLabel, pat)
			if result {
				log.Printf("matchedNamespace: %s, matchedNamespacePattern: %s", namespaceLabel, pat)
			}
		}

		for _, pod := range pods.Items {
			if pod.Namespace == item.Name {
				var podData PodMetrics
				podData.PodName = pod.Name
				podData.Namespace = pod.Namespace
				podData.UID = string(pod.UID)
				podData.HostIP = pod.Status.HostIP
				podData.PodIP = pod.Status.PodIP
				podData.NodeName = pod.Spec.NodeName
				podData.Annotations = pod.Annotations
				podData.HostNetwork = pod.Spec.HostNetwork
				podData.ContainerName = pod.Spec.Containers[0].Name
				podData.ContainerImage = pod.Spec.Containers[0].Image
				podData.ContainerID = pod.Status.ContainerStatuses[0].ContainerID
				podData.Labels = pod.Labels

				for _, labels := range labelsMap {
					result := matchWildcard(pod.Labels[labels.Name], labels.Value)
					if result {
						switch labels.ContainerSelection {
						case "*":
							var containerNames, containerImage, containerId []string
							for _, container := range pod.Spec.Containers {
								containerNames = append(containerNames, container.Name)
								containerImage = append(containerImage, container.Image)
							}
							for _, status := range pod.Status.ContainerStatuses {
								containerId = append(containerId, status.ContainerID)
							}
							podData.ContainerName = strings.Join(containerNames, ", ")
							podData.ContainerImage = strings.Join(containerImage, ", ")
							podData.ContainerID = strings.Join(containerId, ", ")
							break

						case "ALL":
							var containerNames, containerImage, containerId []string
							for _, container := range pod.Spec.Containers {
								containerNames = append(containerNames, container.Name)
								containerImage = append(containerImage, container.Image)
							}
							for _, status := range pod.Status.ContainerStatuses {
								containerId = append(containerId, status.ContainerID)
							}
							podData.ContainerName = strings.Join(containerNames, ", ")
							podData.ContainerImage = strings.Join(containerImage, ", ")
							podData.ContainerID = strings.Join(containerId, ", ")
							break

						case "FIRST":
							podData.ContainerName = pod.Spec.Containers[0].Name
							podData.ContainerImage = pod.Spec.Containers[0].Image
							podData.ContainerID = pod.Status.ContainerStatuses[0].ContainerID
							break

						case "SELECTED":
							for _, container := range pod.Spec.Containers {
								if selectedContainer == container.Name {
									podData.ContainerName = container.Name
									podData.ContainerImage = container.Image
								}
							}
							for _, status := range pod.Status.ContainerStatuses {
								if selectedContainer == status.Name {
									podData.ContainerID = status.ContainerID
								}
							}
							break
						default:
							podData.ContainerName = pod.Spec.Containers[0].Name
							podData.ContainerImage = pod.Spec.Containers[0].Image
							podData.ContainerID = pod.Status.ContainerStatuses[0].ContainerID
						}
						log.Printf("matchedlabel: %s ,  podName: %s\n", labels.Value, pod.Name)
						log.Printf("container Selection: %s, matchedContainer: %v, matchedlabel: %v = %v \n", labels.ContainerSelection, podData.ContainerName, labels.Name, labels.Value)
					}
				}

				namespace.PodsInfo = append(namespace.PodsInfo, podData)
			}
		}

		for _, dep := range deployments.Items {
			if dep.Namespace == item.Name {
				var deployment DepMetrics
				deployment.Name = item.Name
				deployment.UID = string(item.UID)
				deployment.CreatedTimestamp = item.CreationTimestamp.Time
				deployment.Annotations = item.Annotations
				namespace.DepInfo = append(namespace.DepInfo, deployment)
			}
		}

		for _, dae := range daemons.Items {
			if dae.Namespace == item.Name {
				var daemon Daemon
				daemon.Name = dae.Name
				daemon.Namespace = dae.Namespace
				daemon.UID = string(dae.UID)
				daemon.CreatedTimestamp = dae.CreationTimestamp.Time
				daemon.Containers = dae.Spec.Template.Spec.Containers
				namespace.Daemons = append(namespace.Daemons, daemon)
			}
		}

		for _, service := range services.Items {
			if service.Namespace == item.Name {
				var serv Service
				serv.Name = service.Name
				serv.Namespace = service.Namespace
				serv.UID = string(service.UID)
				serv.CreatedTimestamp = service.CreationTimestamp.Time
				serv.Spec = service.Spec
				namespace.Services = append(namespace.Services, serv)
			}
		}

		for _, rep := range replicas.Items {
			if rep.Namespace == item.Name {
				var replica Replica
				replica.Name = rep.Name
				replica.Namespace = rep.Namespace
				replica.UID = string(rep.UID)
				replica.CreatedTimestamp = rep.CreationTimestamp.Time
				namespace.Replicas = append(namespace.Replicas, replica)
			}
		}

		metrics.Namespaces = append(metrics.Namespaces, namespace)
	}

	metricsJSON, _ := json.MarshalIndent(metrics, "", "  ")
	err = os.WriteFile("metricsJSON.json", metricsJSON, 0644)

	if err != nil {
		return fmt.Errorf("failed to write metrics to file: %w", err)
	}

	return nil
}

type Metrics struct {
	NodeTotal  int               `json:"total_node,omitempty"`
	PodsTotal  int               `json:"total_pods,omitempty"`
	NodeInfo   []NodeMetrics     `json:"node_metrics"`
	Namespaces []NamespaceMetric `json:"namespace_metrics"`
}

type NodeMetrics struct {
	// kube_node_annotations
	NodeAddress string `json:"node_address,omitempty"`
	Name        string `json:"node_name,omitempty"`

	// kube_node_info
	KernelVersion           string `json:"kernel_version,omitempty"`
	OsImage                 string `json:"os_image,omitempty"`
	ContainerRuntimeVersion string `json:"container_runtime_version,omitempty"`
	KubeletVersion          string `json:"kubelet_version,omitempty"`
	KubeproxyVersion        string `json:"kubeproxy_version,omitempty"`
	PodCIDR                 string `json:"pod_cidr,omitempty"`
	SystemUUID              string `json:"system_uuid,omitempty"`
	InternalIP              string `json:"internal_ip,omitempty"`

	// kube_node_role
	Role string `json:"role,omitempty"`

	// kube_node_status_capacity
	CapacityCPU              string `json:"capacity_cpu,omitempty"`
	CapacityEphemeralStorage string `json:"capacity_ephemeral_storage,omitempty"`
	CapacityPods             string `json:"capacity_pods,omitempty"`
	CapacityMemory           string `json:"capacity_memory,omitempty"`

	// kube_node_status_allocatable
	AllocatableCPU              string `json:"allocatable_cpu,omitempty"`
	AllocatableEphemeralStorage string `json:"allocatable_ephemeral_storage,omitempty"`
	AllocatablePods             string `json:"allocatable_pods,omitempty"`
	AllocatableMemory           string `json:"allocatable_memory,omitempty"`

	// kube_node_status_condition
	Condition string `json:"condition,omitempty"`
	Status    string `json:"status,omitempty"`

	// kube_node_created
	CreatedTimestamp time.Time `json:"created_timestamp,omitempty"`

	// kube_node_deletion_timestamp
	DeletionTimestamp int64 `json:"deletion_timestamp,omitempty"`
}

type PodMetrics struct {
	// kube_pod_annotations
	PodName   string `json:"pod_name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	UID       string `json:"uid,omitempty"`

	// kube_pod_info
	HostIP      string `json:"host_ip,omitempty"`
	PodIP       string `json:"pod_ip,omitempty"`
	NodeName    string `json:"node_name,omitempty"`
	HostNetwork bool   `json:"host_network,omitempty"`
	Annotations any    `json:"annotations,omitempty"`

	// kube_pod_ips
	IPAddress string `json:"ip_address,omitempty"`
	IPFamily  string `json:"ip_family,omitempty"`

	// kube_pod_start_time
	PodStartTime int64 `json:"pod_start_time,omitempty"`

	// kube_pod_completion_time
	PodCompletionTime int64 `json:"pod_completion_time,omitempty"`

	// kube_pod_owner
	OwnerKind         string `json:"owner_kind,omitempty"`
	OwnerName         string `json:"owner_name,omitempty"`
	OwnerIsController bool   `json:"owner_is_controller,omitempty"`

	// kube_pod_labels
	Labels any `json:"labels,omitempty"`

	// kube_pod_nodeselectors
	NodeSelector string `json:"nodeselector_node_selector,omitempty"`

	// kube_pod_status_phase
	Phase string `json:"phase,omitempty"`
	// kube_pod_status_ready
	ConditionReady string `json:"condition_ready,omitempty"`

	// kube_pod_status_scheduled
	ConditionScheduled string `json:"condition_scheduled,omitempty"`

	// kube_pod_container_info
	ContainerName  string `json:"container_name,omitempty"`
	ContainerImage string `json:"container_image,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`

	// kube_pod_container_status_waiting
	Waiting bool `json:"waiting,omitempty"`

	// kube_pod_container_status_waiting_reason
	WaitingReason string `json:"waiting_reason,omitempty"`

	// kube_pod_container_status_running
	Running bool `json:"running,omitempty"`

	// kube_pod_container_state_started
	ContainerStartTime int64 `json:"container_start_time,omitempty"`

	// kube_pod_container_status_terminated
	Terminated bool `json:"terminated,omitempty"`

	// kube_pod_container_status_terminated_reason
	TerminatedReason string `json:"terminated_reason,omitempty"`

	// kube_pod_container_status_last_terminated_reason
	LastTerminatedReason string `json:"last_terminated_reason,omitempty"`

	// kube_pod_container_status_last_terminated_exitcode
	LastTerminatedExitCode int `json:"last_terminated_exitcode,omitempty"`

	// kube_pod_container_status_last_terminated_timestamp
	LastTerminatedTimestamp int64 `json:"last_terminated_timestamp,omitempty"`

	// kube_pod_container_status_ready
	ContainerReady bool `json:"container_ready,omitempty"`

	// kube_pod_status_initialized_time
	PodInitializedTime int64 `json:"pod_initialized_time,omitempty"`

	// kube_pod_status_ready_time
	PodReadyTime int64 `json:"pod_ready_time,omitempty"`

	// kube_pod_status_container_ready_time
	ContainerReadyTime int64 `json:"container_ready_time,omitempty"`

	// kube_pod_container_status_restarts_total
	ContainerRestartsTotal int `json:"container_restarts_total,omitempty"`

	// kube_pod_container_resource_requests
	ResourceRequestsCPU    string `json:"resource_requests_cpu,omitempty"`
	ResourceRequestsMemory string `json:"resource_requests_memory,omitempty"`
	ResourceRequestsName   string `json:"resource_requests_name,omitempty"`
	ResourceRequestsUnit   string `json:"resource_requests_unit,omitempty"`

	// kube_pod_container_resource_limits
	ResourceLimitsCPU    string `json:"resource_limits_cpu,omitempty"`
	ResourceLimitsMemory string `json:"resource_limits_memory,omitempty"`
	ResourceLimitsName   string `json:"resource_limits_name,omitempty"`
	ResourceLimitsUnit   string `json:"resource_limits_unit,omitempty"`

	// kube_pod_overhead_cpu_cores
	OverheadCPUCores string `json:"overhead_cpu_cores,omitempty"`

	// kube_pod_overhead_memory_bytes
	OverheadMemoryBytes string `json:"overhead_memory_bytes,omitempty"`

	// kube_pod_runtimeclass_name_info
	RuntimeClassName string `json:"runtime_class_name,omitempty"`

	// kube_pod_created
	PodCreatedTimestamp int64 `json:"pod_created_timestamp,omitempty"`

	// kube_pod_service_account
	ServiceAccount string `json:"service_account,omitempty"`

	// kube_pod_scheduler
	SchedulerName string `json:"scheduler_name,omitempty"`
}

type NamespaceMetric struct {
	Name             string       `json:"name,omitempty"`
	UID              string       `json:"uid,omitempty"`
	CreatedTimestamp time.Time    `json:"created_timestamp,omitempty"`
	StatusPhase      string       `json:"status_phase,omitempty"`
	PodsInfo         []PodMetrics `json:"pods_metrics,omitempty"`
	DepInfo          []DepMetrics `json:"deployment_metrics,omitempty"`
	Daemons          []Daemon     `json:"daemons_metrics,omitempty"`
	Services         []Service    `json:"services_metrics,omitempty"`
	Replicas         []Replica    `json:"replica_metrics,omitempty"`
}

type DepMetrics struct {
	Name             string    `json:"name,omitempty"`
	UID              string    `json:"uid,omitempty"`
	CreatedTimestamp time.Time `json:"created_timestamp,omitempty"`
	Annotations      any       `json:"annotations,omitempty"`
}

type Daemon struct {
	Name             string    `json:"name,omitempty"`
	Namespace        string    `json:"namespace,omitempty"`
	UID              string    `json:"uid,omitempty"`
	CreatedTimestamp time.Time `json:"created_timestamp,omitempty"`
	Containers       any       `json:"containers,omitempty"`
}

type Service struct {
	Name             string    `json:"name,omitempty"`
	Namespace        string    `json:"namespace,omitempty"`
	UID              string    `json:"uid,omitempty"`
	CreatedTimestamp time.Time `json:"created_timestamp,omitempty"`
	Spec             any       `json:"spec,omitempty"`
}

type Replica struct {
	Name             string    `json:"name,omitempty"`
	Namespace        string    `json:"namespace,omitempty"`
	UID              string    `json:"uid,omitempty"`
	CreatedTimestamp time.Time `json:"created_timestamp,omitempty"`
	//Spec             any       `json:"spec,omitempty"`
}

func matchWildcard(s, pattern string) bool {
	if pattern == "" {
		return s == ""
	}

	if pattern[0] == '*' {
		for i := 0; i <= len(s); i++ {
			if matchWildcard(s[i:], pattern[1:]) {
				return true
			}
		}
		return false
	}

	if len(s) == 0 || (pattern[0] != '?' && s[0] != pattern[0]) {
		return false
	}

	return matchWildcard(s[1:], pattern[1:])
}

type Config struct {
	Apiversion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		Features struct {
			APM struct {
				Enabled             bool     `yaml:"enabled"`
				WorkLoadsToMonitor  []string `yaml:"workLoadsToMonitor"`
				MonitoredNamespaces []string `yaml:"monitoredNamespaces"`
				IgnoredNamespaces   []string `yaml:"ignoredNamespaces"`
				Java                struct {
					Enabled       bool     `yaml:"enabled"`
					LabelsToMatch []Labels `yaml:"labelsToMatch"`
					Config        struct {
						EgBtmSetLabel string `yaml:"egBtmSetLabel"`
					} `yaml:"config"`
				} `yaml:"java"`
			} `yaml:"apm"`
		} `yaml:"features"`
	} `yaml:"spec"`
}

type Labels struct {
	Name               string `yaml:"name"`
	Value              string `yaml:"value"`
	ContainerSelection string `yaml:"containerSelection"`
}
