class Host:

    def __init__(self, ip, hostname="Unknown"):

        self.ip = ip

        self.hostname = hostname

        self.mac = "Unknown"

        self.open_ports = []

        self.services = {}

        self.banners = {}
