
import logging
import traceback
import urllib3
#logging.basicConfig(filename='px.log', encoding='utf-8', level=logging.DEBUG)
logging.basicConfig( level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.WARNING)

from WindowsNode import WindowsNode
from ConfigInjector import ConfigInjector
from Config import Config
from ProbeConnectCheck import ProbeConnectCheck
import json
import requests

class UdpWindowsDeployer():

    def __init__( self, config, targetHostName, targetUserName, targetPassword, targetCert  ):
        self.config = config.getConfig()
        self.targetConfig = self.config["enclave"]["udp"]

        self.basePath = self.config["basePath"]
        self.tempPath = self.config["tempPath"]
        self.templateFile = self.targetConfig["templateFile"]
        self.binFile = self.targetConfig["binFile"]
        self.installPath = self.targetConfig["installPath"]

        print( "%s- %s " % (targetUserName, targetPassword))

        self.wn = WindowsNode( targetHostName,  targetUserName, targetPassword )

        logging.info("UDP Windows deployer initialized.")

    def preCheck( self, byPassExistingService = False ):
        self.nodeConfig = self.wn.getNodeConfiguration()
        if self.wn.testConnection() == False:
            logging.critical("Unable to connect to server: %s" % self.targetHostName )
            raise Exception( "Unable to connect to server: %s" % self.targetHostName )

        (result, data, error ) = self.wn.executePS("(Get-Service -Name \"UCMDB Probe*\").Status" )
        if data.strip().lower() != "":
            logging.warn("UCMDB Probe already installed: Service Satus: %s" % data.strip() )
            if not byPassExistingService:
                logging.critical("Aborting installation")
                raise Exception("UCMDB Probe already installed: Service Satus: %s" % data.strip())

    def injectConfig( self ):
        self.ci = ConfigInjector( self.basePath + self.templateFile )
        self.ci.inject("USER_INSTALL_DIR", ( self.installPath % "C:").replace("\\", "\\\\") )
        self.ci.inject("PROBE_PARAM_4", self.config["core"]["ucmdb"]["hostName"] )
        self.ci.inject("PROBE_PARAM_6", self.config["targets"]["udp"]["hostName"][0] )
		
        self.ci.inject("MAMPROBE_PASSWORD", self.config["enclave"]["udp"]["mamProbePassword"] )
        self.ci.inject("MAMPROBE_PASSWORD_VER", self.config["enclave"]["udp"]["mamProbePassword"] )
        self.ci.inject("ROOT_PASSWORD", self.config["enclave"]["udp"]["rootPassword"] )
        self.ci.inject("ROOT_PASSWORD_VER", self.config["enclave"]["udp"]["rootPassword"] )
        self.ci.inject("SYSADMIN_USER_PASSWORD", self.config["enclave"]["udp"]["systemAdminPassword"] )
        self.ci.inject("SYSADMIN_USER_PASSWORD_VER", self.config["enclave"]["udp"]["systemAdminPassword"] )
        self.ci.inject("UPLOADSCAN_PASSWORD", self.config["enclave"]["udp"]["uploadScanPassword"] )
        self.ci.inject("UPLOADSCAN_PASSWORD_VER", self.config["enclave"]["udp"]["uploadScanPassword"])
        self.ci.saveConfig( "/tmp/silentudp.txt" )
        logging.info("config file generated")

    def transport( self ):
        self.wn.upload(  self.basePath + self.binFile, self.tempPath + "/UCMDB_DataFlowProbe_2020.08.exe" )
        logging.info("Binary copied successfully")
        self.wn.upload(  "/tmp/silentudp.txt", self.tempPath + "/silentudp.txt" )
        logging.info("Silent properties copied successfully")
        logging.info("Silent properties copied successfully")

    def install( self ):
        print(self.tempPath + "/UCMDB_DataFlowProbe_2020.08.exe -i silent -f " + self.tempPath + "/silentudp.txt")
        (result, data, error ) = self.wn.executePS( self.tempPath + "/UCMDB_DataFlowProbe_2020.08.exe -i silent -f " + self.tempPath + "/silentudp.txt")
        (result, data, error ) = self.wn.executePS("(Get-Service -Name \"UCMDB Probe\").Status" )
        if data.strip().lower() == "running":
            logging.warn("UCMDB Probe  running, Stopping service, Status: %s" % data.strip() )
            (result, data, error ) = self.wn.executePS("(Get-Service -Name \"UCMDB*Probe\").Stop()" )
        print("(Get-Content "+(self.installPath % "C:") +"\\conf\\DataFlowProbe.properties).replace('8443', '443') | Set-Content " + (self.installPath % "C:") +"\\conf\\DataFlowProbe.properties")
        (result, data, error ) = self.wn.executePS("(Get-Content "+(self.installPath % "C:") +"\\conf\\DataFlowProbe.properties).replace('8443', '443') | Set-Content " + (self.installPath % "C:") +"\\conf\\DataFlowProbe.properties")
        (result, data, error ) = self.wn.executePS(self.installPath % "C:" +"\\bin\gateway.bat start")
        logging.info( result )
        logging.info( data )
        logging.info( error )

    def validate( self ):
        
		#Check probe install log
		check_install="Get-ChildItem -Path "+(self.installPath % "C:") + "\\UninstallerData\\Logs\\UCMDB_Data_Flow_Probe_Install\*.log " + "| Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Select-String -Pattern 'Successful'"
		(result, data, error ) = self.wn.executePS(check_install)
		if "Installation: Successful." in data:
			logging.info("Data Flow Probe Installation is successful")
		else:
			logging.error("Data Flow Probe Installation failed")
			return
		
		## TODO: CHANGE SERVIE NAME
        (result, data, error ) = self.wn.executePS("(Get-Service -Name \"UCMDB*Probe\").Status" )
        if data.strip().lower() != "running":
            logging.warn("UCMDB Probe not running, attempting to start, Status: %s" % data.strip() )
            (result, data, error ) = self.wn.executePS("(Get-Service -Name \"UCMDB*Probe*\").Start()" )
            if result != 0:
                logging.error("Failed to start service")
                return
				
		#Check if probe connected to UCMDB
		
		payload_test = {"username": self.config["credentials"][0].["userName"],
						"password": self.config["credentials"][0].["password"], 
						"clientContext": 1
						}
		api_url_base = self.config["core"]["ucmdb"]["url"]
		api_url = api_url_base + "/rest-api/authenticate"
		response = requests.post(api_url, json=payload_test)
		if response.status_code == 200:
			added_key = json.loads(response.content)
 
		api_token = added_key
		api_url = api_url_base + "/rest-api/dataflowmanagement/probes"
		headers = {'Content-Type': 'application/json',
				    'Authorization': 'Bearer {0}'.format(api_token)}
			
		response = requests.get(api_url, headers=headers)

		if response.status_code == 200:
			response_content = json.loads(response.content.decode('utf-8'))
			if self.config["targets"]["udp"]["hostName"][0] in response_content:
				logging.info("Data Flow Probe is connected")
			else:
				logging.warn("Data Flow Probe is not connected")
		
 
		
		
			

    def cleanUp( self ):
        self.wn.removeFile( self.tempPath + "/silent.properties" )
        self.wn.removeFile( self.tempPath + "UCMDB_DataFlowProbe_2020.08.exe" )
        logging.info("File successfuly removed")

    def configureContent( self ):
        logging.info("No content to deploy")

    def integrate( self ):
        logging.info("No integration to do")

    def deploy( self ):
        try:
            self.preCheck( byPassExistingService = False )
            self.injectConfig()
            self.transport()
            self.install()
            self.validate()
            self.cleanUp()
            self.configureContent()
            self.integrate()
        except Exception as e:
            error_message = getattr(e, 'message', repr(e))
            error_description = traceback.format_exc()
            logging.critical(error_message)
            logging.critical(error_description)



config = Config()
( targetHostNames, (targetUserName, targetPassword, targetCert) ) = config.getTarget("udp")
for targetHostName in targetHostNames:
    logging.info("Deploying UDP on %s" % targetHostName )
    deployer = UdpWindowsDeployer( config, targetHostName, targetUserName, targetPassword, targetCert)
    deployer.deploy()
