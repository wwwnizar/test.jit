class MessageMock:
    """ Can't mock confluent_kafka.Message since it's implemented in C. Instead,
    this class replaces it and implements the relevant function calls.
    (Unlike Producer and Consumer, Message is not user-instantiable.
    This is why it is replaced and not simply wrapped.)"""

    def __init__(self, topic, partition, offset, key, value):
        self._topic = topic
        self._partition = partition
        self._offset = offset
        self._key = key
        self._value = value

    def topic(self):
        return self._topic

    def partition(self):
        return self._partition

    def offset(self):
        return self._offset

    def key(self):
        return self._key.encode('utf-8')

    def value(self):
        return self._value.encode('utf-8')

    def error(self):
        return None
