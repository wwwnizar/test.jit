# scan-worker
A Kubernetes worker that pulls from a Kafka queue and performs a [detect-secrets](https://github.com/IBM/detect-secrets) scan.

Adapted from [this Kubernetes tutorial](https://kubernetes.io/docs/tasks/job/fine-parallel-processing-work-queue/) and [this IBM Event Streams code sample](https://github.com/ibm-messaging/event-streams-samples/tree/master/kafka-python-console-sample).
