
class ByteQueue():

    data = b''

    def __init__(self, data=b''):

        self.data = bytes(data)

    def enqueue(self, data):

        self.data = self.data + data

    def dequeue(self, data_length=1):

        data = self.data[:data_length]
        self.data = self.data[data_length:]
        return data

    def __len__(self):

        return len(self.data)

    def __repr__(self):

        return 'ByteQueue(b\'%s\')' % self.data


if __name__ == '__main__':

    queue = ByteQueue(b'123')
    print(queue)
    print(len(queue))
    queue.enqueue(b'567')
    print(queue)
    print(len(queue))
    print(queue.dequeue(3))
    print(queue)
