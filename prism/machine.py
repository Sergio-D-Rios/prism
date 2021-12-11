class Machine():

    def __init__(self, 
                 ip, 
                 protocols: list=None, 
                 conversation_types: list=None,
                 associated_machines: list=None,
                 conversations: list=None,
                 classification: str=None):
        self.ip = ip
        self.protocols = protocols or []
        self.conversation_types = conversation_types or []
        self.associated_machines = associated_machines or []
        self.conversations = conversations or []
        self.classification = classification or ""

    def __str__(self):

        print_str = (f'IP: {self.ip}'
                     f' Classification: {self.classification}'
                     f' Protocols: {self.protocols}'
                     f' Conversation Types: {self.conversation_types}'
                     f' Associated Machines: {self.associated_machines}'
                     f' Conversations: {self.conversations}')

        return print_str

    def visualizer_str(self):
        conversation_str = 'Conversations:'
        for conversation in self.conversations:
            conversation_str += f'<br>{conversation}'

        print_str = (f'IP: {self.ip}<br>'
                     f'Classification: {self.classification}<br>'
                     f'Protocols: {self.protocols} <br>'
                     f'Conversation Types: {self.conversation_types} <br>'
                     f'Associated Machines: {self.associated_machines} <br>'
                     f'{conversation_str}')

        return print_str


        

    
        