import asyncio



class Message:
    def __init__(self, queue):
        self.queue = queue

    """ 
    Give: Method takes two arguments and a shared workload queue. 
    Adds a mapping - a key value pair id:value into the queue which can later be used by the other client.
    queue: [{id:value}]

    """
    async def give(self, tag, value):
        if self.queue.empty():
            tags = {tag: value}
            await self.queue.put(tags)
        else:
            tags = await self.queue.get()
            if tags.get(tag) is None:
                tags[tag] = value
            await self.queue.put(tags)

    """ 
    Get: Method takes id and a shared workload queue. 
    Gets the id element or waits till it is populated and returns the same.
    """

    async def get(self, tag):
        if self.queue.empty():
            print("Queue is Empty. Unable to get any elements yet.")
            await asyncio.sleep(0.2)
            await self.get(tag)
        tags = await self.queue.get()
        await self.queue.put(tags)
        if tags.get(tag) is None:
            await asyncio.sleep(0.2)
            await self.get(tag)
        tag_val = tags.get(tag)
        return tag_val