from pyvis.network import Network

class Visualizer():

    def __init__(self):
        self.net_graph = Network(height='100%', 
                                 width='100%', 
                                 bgcolor='#222222', 
                                 font_color='white',
                                 heading="Network Analysis Result")
        self.net_graph.barnes_hut()

    def add_machines(self, machines: list=[]):
        color = 'grey'
        
        # First need to add all nodes
        for machine in machines:
            if machine.classification == 'PLC':
                color = 'blue'
            elif machine.classification == 'HMI':
                color = 'green'
            elif machine.classification == 'Alarm':
                color = 'red'

            desc_str = machine.visualizer_str()
            self.net_graph.add_node(machine.ip, 
                                    label=machine.ip,
                                    title=desc_str,
                                    color=color)

        # Then we need to add all conversations
        for machine in machines:
            for conversation in machine.conversations:
                self.net_graph.add_edge(conversation[0],conversation[1])

    def show(self):
        self.net_graph.show('network.html')
