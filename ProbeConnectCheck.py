import com.hp.schemas.ucmdb.discovery._1.params.IsProbeConnectedRequest
import com.hp.schemas.ucmdb.discovery._1.params.IsProbeConnectedRequestDocument
import com.hp.schemas.ucmdb.discovery._1.params.IsProbeConnectedResponceDocument
import com.hp.ucmdb.generated.DiscoveryServiceStub
from Config import Config
import org.apache.axis2.transport.http.HTTPConstants
import org.apache.axis2.transport.http.HttpTransportProperties
import com.hp.schemas.ucmdb._1.types.CmdbContext


class ProbeConnectCheck:
		
	
	def __init__(self):
        HOST_NAME = self.config["core"]["ucmdb"]["hostName"]
		PORT = self.config["core"]["ucmdb"]["port"]
		PROTOCOL = "https";
		FILE = "/axis2/services/DiscoveryService";
		PASSWORD = self.config["credentials"][0].["password"]
		USERNAME = self.config["credentials"][0].["userName"]
		CmdbContext cmdbContext = CmdbContext.Factory.newInstance()

    def __del__( self ):
        pass
	
	def getService(self):
		DiscoveryServiceStub serviceStub=null;
		try:
				URL url = new URL(PROTOCOL, HOST_NAME, PORT, FILE)
				serviceStub = new DiscoveryServiceStub(url.toString())
				HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator()
				auth.setUsername(USERNAME)
				auth.setPassword(PASSWORD)
				serviceStub._getServiceClient().getOptions().setProperty(HTTPConstants.AUTHENTICATE, auth)
		except:
				print("Cannot connect to UCMDB")

		return serviceStub;
	
	
	def isProbeConnected(self,domainName,probeName):
		serviceStub = getService()
		cmdbContext.setCallerApplication("isProbeConnected")
		IsProbeConnectedRequest isProbeConnectedRequest = IsProbeConnectedRequest.Factory.newInstance()
		isProbeConnectedRequest.setCmdbContext(cmdbContext)
		isProbeConnectedRequest.setDomainName(domainName)
		isProbeConnectedRequest.setProbeName(probeName)

		IsProbeConnectedRequestDocument isProbeConnectedRequestDocument = IsProbeConnectedRequestDocument.Factory.newInstance()
		isProbeConnectedRequestDocument.setIsProbeConnectedRequest(isProbeConnectedRequest)

		IsProbeConnectedResponceDocument IsProbeConnectedResponceDocument = serviceStub.isProbeConnected(isProbeConnectedRequestDocument)
		print(IsProbeConnectedResponceDocument.getIsProbeConnectedResponce())
		

