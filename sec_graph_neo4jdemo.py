from py2neo import neo4j
#Connection 
graph_db = neo4j.GraphDatabaseService("http://localhost:7474/db/data/")

#Build relevant indexes
incs = graph_db.get_or_create_index(neo4j.Node,"incs")
tips = graph_db.get_or_create_index(neo4j.Node,"tips")
threat_groups = graph_db.get_or_create_index(neo4j.Node,"threat_groups")
hashes = graph_db.get_or_create_index(neo4j.Node,"hashes")
domains = graph_db.get_or_create_index(neo4j.Node,"domains")
subdomains = graph_db.get_or_create_index(neo4j.Node,"subdomains")
ips = graph_db.get_or_create_index(neo4j.Node,"ips")
phishes = graph_db.get_or_create_index(neo4j.Node,"phishes")
brute_attacks = graph_db.get_or_create_index(neo4j.Node,"brute_attacks")
senders = graph_db.get_or_create_index(neo4j.Node,"senders")
users = graph_db.get_or_create_index(neo4j.Node,"users")
devices = graph_db.get_or_create_index(neo4j.Node,"devices")
departments = graph_db.get_or_create_index(neo4j.Node,"departments")
offices = graph_db.get_or_create_index(neo4j.Node,"offices")
service_tickets = graph_db.get_or_create_index(neo4j.Node,"service_tickets")
sources = graph_db.get_or_create_index(neo4j.Node,"sources")
exploits = graph_db.get_or_create_index(neo4j.Node,"exploits")
signatures = graph_db.get_or_create_index(neo4j.Node,"signatures")
security_tools = graph_db.get_or_create_index(neo4j.Node,"security_tools")
threat_actors = graph_db.get_or_create_index(neo4j.Node,"threat_actors")


def addIp(ip):
	return graph_db.get_or_create_indexed_node("ips", "ip", ip, {"ip": ip, "asn" : "AS56402", "blocked_in": "false", "blocked_out": "false"})
	
def addDomain(domain, registrant_email, blocked_out, sinkholed, whitelist):
	return graph_db.get_or_create_indexed_node("domains", "domain", domain, {"domain": domain, "registrant_email": registrant_email, "blocked_out":blocked_out, "sinkholed":sinkholed, "whitelist":whitelist})

def addHash(malhash, filename, malicious, blacklisted):
	return graph_db.get_or_create_indexed_node("hashes", "hash", malhash, {"hash":malhash, "filename": filename, "automal" : "relevant results from sandbox go here", "malicious" : malicious , "blacklisted": blacklisted})





#Security and Environment Data (non intel/event driven)

nitro = graph_db.get_or_create_indexed_node("security_tools", "security_tool", "nitro", {"security_tool":"nitro", "version":"4.0", "updated":"20131008"})

sourcefire = graph_db.get_or_create_indexed_node("security_tools", "security_tool", "sourcefire", {"security_tool":"sourefire", "version":"2.2", "updated":"20131009"})

fireeye = graph_db.get_or_create_indexed_node("security_tools", "security_tool", "fireeye", {"security_tool":"fireeye", "version":"3.2", "updated":"20131009" })

damballa = graph_db.get_or_create_indexed_node("security_tools", "security_tool", "damballa", {"security_tool":"damballa", "version":"4.3", "updated":"20131009" })

paloalto = graph_db.get_or_create_indexed_node("security_tools", "security_tool", "paloalto", {"security_tool":"paloalto", "version":"3.2", "updated":"20131009" })

mir = graph_db.get_or_create_indexed_node("security_tools", "security_tool", "mir", {"security_tool":"mir", "version":"5.2", "updated":"20131009" })


#Security Signatures 

win_troj_apt_greencat_c2 = graph_db.get_or_create_indexed_node("signatures", "signature", "win_troj_apt_greencat_c2", {"signature":"win_troj_apt_greencat_c2", "notes":"Detects C2 communication protocol for 'Greencat' malware","security_tool":["sourcefire"],"date":20131008,"path_to_sig":"path/to/signature"})

cf_rtf_cve_2012_0158_var1_objocx = graph_db.get_or_create_indexed_node("signatures", "signature", "cf_rtf_cve_2012_0158_var1_objocx", {"signature":"cf_rtf_cve_2012_0158_var1_objocx", "notes":"Detects CVE 2012-0158 in DOC and RTF Carrier files", "security_tool":["fireye"],"date":20131007,"path_to_sig":"path/to/signature"})

correlation_malicious_senders = graph_db.get_or_create_indexed_node("signatures", "signature", "correlation_malicious_senders", {"signature":"correlation_malicious_senders", "notes":"List of Known Malicious Email Senders", "security_tool":["nitro"],"date":20131007,"path_to_sig":"path/to/signature"})

correlation_malicious_ips = graph_db.get_or_create_indexed_node("signatures", "signature", "correlation_malicious_ips", {"signature":"correlation_malicious_ips", "notes":"List of Known Malicious IPs", "security_tool":["nitro","damballa"],"date":20131007,"path_to_sig":"path/to/signature"})

correlation_malicious_domains = graph_db.get_or_create_indexed_node("signatures", "signature", "correlation_malicious_domains", {"signature":"correlation_malicious_domains", "notes":"List of Known Malicious Domains", "security_tool":["nitro","paloalto"],"date":20131007,"path_to_sig":"path/to/signature"})

mirscan_malicious_files = graph_db.get_or_create_indexed_node("signatures", "signature", "mirscan_malicious_files", {"signature":"mirscan_malicious_files", "notes":"List of Known Malicious Domains", "security_tool":["mir"],"date":20131008,"path_to_sig":"path/to/signature"})

# Exploits

CVE_2012_0158 = graph_db.get_or_create_indexed_node("exploits", "exploit", "CVE-2012-0158", {"exploit":"CVE-2012-0158", "cvss": 9.3, "vuln_sw": "MS Office 2003-2010"})

#Threat Groups and Actors

webc2 = graph_db.get_or_create_indexed_node("threat_groups", "threat_group", "webc2", {"threat_group": "webc2", "aliases": ["comment crew","apt1","shadyrat","comment panda"], "country": "china", "notes": "Analyst Notes on attribution go here", "threat_class": "espionage", "references": ["url","url"]})
sea = graph_db.get_or_create_indexed_node("threat_groups", "threat_group", "sea", {"threat_group": "sea", "aliases": ["syrian electronic army"], "country": "syria", "notes": "Analyst Notes on attribution go here", "threat_class": "hactivisim", "references": ["url","url"]})

dnscalc = graph_db.get_or_create_indexed_node("threat_groups", "threat_group", "dnscalc", {"threat_group": "dnscalc", "aliases": ["ixushe", "dyncalc", "numbered panda", "apt12"], "country": "china", "notes": "Analyst Notes on attribution go here", "threat_class": "espionage", "references": ["url","url"]})

uglymonkey = graph_db.get_or_create_indexed_node("threat_actors", "threat_actor", "uglymonkey", {"threat_actor": "uglymonkey", "country": "china", "facebook" : "uglymonkey", "twitter":"@monkeybutt",  "email" : "monkeybutt@google.com","notes": "Analyst Notes on attribution go here", "references": ["url","url"]})

pownyou2 = graph_db.get_or_create_indexed_node("threat_actors", "threat_actor", "pownyou2", {"threat_actor": "pownyou2", "country": "korea", "facebook" : "pownyou2", "twitter":"@pownyou2",  "email" : "pownyou2@google.com","notes": "Analyst Notes on attribution go here", "references": ["url","url"]})



#Business Data

office_cso = graph_db.get_or_create_indexed_node("departments", "department", "Office of CSO", {"department":"Office of CSO"})
sec_ops = graph_db.get_or_create_indexed_node("departments", "department", "Security Operations", {"department":"Security Operations"})
executives = graph_db.get_or_create_indexed_node("departments", "department", "Executive Leadership", {"department":"Executive Leadership"})

washington_dc = graph_db.get_or_create_indexed_node("offices", "office", "washington", {"office":"Washington", "address":"1600 Pennsylvania Ave  Washington, DC 20001", "country":"USA", "airport":"DCA"})
sanfrancisco_ca = graph_db.get_or_create_indexed_node("offices", "office", "fribourg", {"office":"San Fransciso", "address":"1 Market Street  San Francisco, CA 90210", "country":"USA", "airport":"SFO"})

kpoole = graph_db.get_or_create_indexed_node("users", "user", "kpoole", {"user":"kpoole", "email":"kpoole@examplecorp.com","title":"Director of Security Operations",  "first_name": "Kara", "last_name": "Poole"})
lcolon = graph_db.get_or_create_indexed_node("users", "user", "lcolon", {"user":"lcolon", "email":"lcolon@examplecorp.com","title":"Sr. Manager Security Operations",  "first_name": "Loren", "last_name": "Colon"})
ggreene = graph_db.get_or_create_indexed_node("users", "user", "ggreene", {"user":"ggreene", "email":"ggreene@examplecorp.com","title":"Sr. Manager Threat Intelligence",  "first_name": "Gerard", "last_name": "Greene"})
lmassey = graph_db.get_or_create_indexed_node("users", "user", "lmassey", {"user":"lmassey", "email":"lmassey@examplecorp.com","title":"Director of Threat Intelligence",  "first_name": "Leo", "last_name": "Massey"})
bhayes = graph_db.get_or_create_indexed_node("users", "user", "bhayes", {"user":"bhayes", "email":"bhayes@examplecorp.com","title":"CSO",  "first_name": "Brian", "last_name": "Hayes", "vip": "true"}) 
ddaniels = graph_db.get_or_create_indexed_node("users", "user", "ddaniels", {"user":"ddaniels", "email":"ddaniels@examplecorp.com","title":"Sr. Countermeasures Engineer", "first_name": "Dorothy", "last_name": "Daniels"})
sbennett = graph_db.get_or_create_indexed_node("users", "user", "sbennett", {"user":"sbennett", "email":"sbennett@examplecorp.com","title":"President and CEO", "first_name": "Sammy", "last_name": "Bennett", "vip":"true"})

VRZ3984827 = graph_db.get_or_create_indexed_node("devices", "device", "VRZ3984827", {"device":"VRZ3984827", "type":"server", "os":"redhat"})
VRZ398ES = graph_db.get_or_create_indexed_node("devices", "device", "VRZ398ES", {"device":"VRZ398ES", "type":"laptop", "os":"osx"}) 
VRZ398BB = graph_db.get_or_create_indexed_node("devices", "device", "VRZ398BB", {"device":"VRZ398BB", "type":"laptop", "os":"osx"})

#Indicators/Events Originating to TIP131000001

TIP131000001 = graph_db.get_or_create_indexed_node("tips", "tip", "TIP131000001", {"tip": "TIP131000001", "source": "OSI", "notes": "http://www.secureworks.com/cyber-threat-intelligence/threats/htran/", "tlp": "white","attached_files": ["path/to/file/one","path/to/file/two"], "date": 20131007})
TIP131000001["status"] = "complete"

webc2_phisher = graph_db.get_or_create_indexed_node("senders", "sender", "webc2_phisher@gmail.com", {"sender": "webc2_phisher@gmail.com", "email_domain": "gmail.com"})

ip77777777 = graph_db.get_or_create_indexed_node("ips", "ip", "77.77.77.77", {"ip":"77.77.77.77", "asn" : "AS56402", "blocked_in": "false", "blocked_out": "true"})

ip212125200204 = graph_db.get_or_create_indexed_node("ips", "ip", "212.125.200.204", {"ip":"212.125.200.204", "asn" : "AS3292", "blocked_in": "true", "blocked_out": "true"})

mantech_blackcake_net = graph_db.get_or_create_indexed_node("subdomains", "subdomain", "mantech.blackcake.net", {"subdomain":"mantech.blackcake.net", "domain":"blackcake.net", "blocked_out":"true", "sinkholed":"true"})

BLK111 = graph_db.get_or_create_indexed_node("service_tickets", "service_ticket", "BLK111", {"service_ticket":"BLK111", "type":"ip block", "status":"complete"})

SNK111 = graph_db.get_or_create_indexed_node("service_tickets", "service_ticket", "SNK111", {"service_ticket":"SNK111", "type":"dns sinkhole", "status":"complete"})

gmail_com = graph_db.get_or_create_indexed_node("domains", "domain", "gmail.com", {"domain":"gmail.com", "registrant_email":"admin@google.com", "blocked_out": "false", "sinkholed":"false", "whitelist":"true"})

ip20985216176 = graph_db.get_or_create_indexed_node("ips", "ip", "209.85.216.176", {"ip":"209.85.216.176", "asn" : "AS15169", "blocked_in": "false", "blocked_out": "false", "whitelist" : "true"})

#Indicators/Events Originating to TIP131000002

TIP131000002 = graph_db.get_or_create_indexed_node("tips", "tip", "TIP131000002", {"tip": "TIP131000002", "source": "DHS", "notes": "http://www.dhsportal/thread?23", "tlp": "amber","attached_files": ["path/to/file/one","path/to/file/two"], "date": 20131017})
TIP131000002["status"] = "open"
BLK113 = graph_db.get_or_create_indexed_node("service_tickets", "service_ticket", "BLK113", {"service_ticket":"BLK113", "type":"ip block", "status":"open"})
SNK112 = graph_db.get_or_create_indexed_node("service_tickets", "service_ticket", "SNK112", {"service_ticket":"SNK112", "type":"sinkhole", "status":"complete"})

iplist = []
for n in range(50,80):
	iplist.append("77.77.77." +str(n))

for ip in iplist:
	ipnode = addIp(ip)
	#ipnode['blocked_out'] = 'true'
	#ipnode['blocked_in'] = 'true'
	graph_db.get_or_create_relationships((TIP131000002, "C2", ipnode, {"port": 443}), (BLK113, "BLOCKS", ipnode) ,(correlation_malicious_ips, "DETECTS", ipnode))

hashlist = ["b3530b7519660996d28eb31a8d5b585ec60601843c77dd9f2b712812c99843e4", "347b21e94912e99fb312153948d1f2758454e136", "a8e0d4771c1f71709ddb63d9a75dc895", "496aafad60d5b31fd8aa6d7047142a304dff67f3b9b2782473683a94c185af17", "5d5671d0e2f8cc23d3627fe9a75c091cde060668", "d515fe1b4d8290ec7155fc6d4653ce70", "3cb5663db8298c9e76ae07f21122b04116ee2d5853dfcf51522a8c653453b101", "b1bcfbad5c4b32c8217b938b98eebd41d5f89a9f", "61c9b787e54984ea36743586dffd2b70", "661400a3a9b59a29ab7d2c3ca631f9b9c56609a84fb67879bfabe255d2acc7a4", "10d51e376b94929257a93695d8f7c04deb82b778", "11800c67cf83acd8a206a2398781c132", "cd9c7f6ad8dd68ac734730db0f69784919588f4cec59ebfeeeb89c366e6b74ae", "f71613d8327a46c8fcbcaa4bbfe5226687ee4041", "ac537566c3f67461166296a2b8259cdf", "9454b449b35fc9906be24963dbedc0762e1bdbf9ac6675e45a1d79868cecb77a", "4c9f3558a96873b4ee9a054a8e4c8d04e6dd24f1", "d6bb5d0d1a8f90a4eb8a5e9d53af5544", "b929ae6f3cad8ac270093b9edec954bc64400622c486744e8c03f1fc48cd2b57", "b5ab73ccd7384502f64bc674b35236ccb32dfd1e", "e8a1043619ba961605a570b7a6c05326", "78032f30353f70303a51b20607dbcca9ed9ba2b727adb75c6b82e3c489a6f6a7", "49dc9fb413408a4e436fce80c0acffe0df91c7d9", "1b4f157d7bb31b038dc0b120ebb98482", "7fd403d5a31cc6d78ac51229ff32c9e54346966c8ab1be7eafce4c07f11e0332", "65c21daa5255e39ec84d353ab860fc2cde68aa6d", "786deec36e0e40e64ddc68cade0f18c4", "b0da1dcd91a19dcce0d37108d51d818ea3350d0fd03380e58cbc535d61bab26b", "efd539dfa8f9d6c29b4be80c15a2aa5dd937c1f6", "defdcfb6cafb39d352a175f72737dca2", "6adb62d779df08a48c7a627fb1cd05e04536aa4e361dc7dfe1c5925dd828be18", "14b377da7585db2de9007d935f7d6059bd3fb7e6", "de95080b27d41e93a87f66cb9b15cd05", "9bb27ef9b62e6e3a1917fdef753209644e1743fffba9f8668d289acb2d172a48", "89f35f34f63bddf0f18adb28f98df9c2a3e9c9e7", "ba12cfc9782728dc500d384264a33ea1", "e18fdba195790635ee9950cef391ca1859daaf1af56903866c8d98ed2a117aa1", "7ef915c479958f06c4ab250a2c24f1cc77556335", "6b6f59c3e6842fea29b482eaa52c4f00", "ecd588a48df67e527db79d896312040f7b67b9d67657ea99e9078513ddba38e4", "6adad8d045456928df4d03a4024452e4b2ba3db2", "8162a3fdadcb876219ac51037bd0a09b", "a82bbb5d176d35cf896e5af2c2f8d9ee8b65b1674a30c69e9eea9eb67cd03bf8", "b13a859cb21d5bd6ad6a1382a7d99429c5856c59", "dc63287dc65d45b0808942d96277aec9", "6acec4c102ab578dff844e20655170d951faed5beb0d205e6934784514e9b677", "02145594d872e8a3e7e26cd57351cb5c93f63ac3", "ded5f6196a45eadded4079cc522793b7", "3e09f89f692455a55a8553e503eda34b961a10eda0937ac8aa56f14b6d592948", "230804eba3fe98d07170d2d16dc5a9f03cb8f815", "2a61357f1110a6234fcc52b265e3dcf9", "ec96745f1640cef71c8aa6b753a409e62d628d7faf5e65f4ba0b4bd66508fe1f", "03c9b86e7bc0e50aa41e1b879170cd5ab551cf6c", "5fec7695104b4189253a9c25619c8b71", "bcd46ee428da616376ef5985fb8d8e7fecf93259ab8c84431ed90593629198bc", "f8c5b2e45582311350f6f1217df0b8f879961f82", "0b68a56abdfd165034598b0270b0a29b", "be7c05aafc2d8b05b08b63f196c18264bc28f183955cf64fbc7add198194913b", "c98d7ff96ea31841411b291c119128c05c2f0d7b", "941eca8c96c5fd2caf9b0107d63a9ae3"]

#Indicators/Events Originating to TIP131000003

TIP131000003 = graph_db.get_or_create_indexed_node("tips", "tip", "TIP131000003", {"tip": "TIP131000002", "source": "OSI", "notes": "SEA Compromised .qa registry", "tlp": "white","attached_files": ["path/to/file/one","path/to/file/two"], "date": 20131019})
TIP131000003["status"] = "closed"
correlation_qatar_tld = graph_db.get_or_create_indexed_node("signatures", "signature", "correlation_qatar_tld", {"signature":"correlation_qatar_tld", "notes":"Alert on traffic to compromised TLD", "security_tool":["nitro","paloalto"],"date":20131019,"path_to_sig":"path/to/signature"})
google_qa = addDomain("google.qa", "admin@google.com", "false", "false", "true")
facebook_qa = addDomain("facebook.qa", "admin@google.com", "false", "false", "true")
graph_db.get_or_create_relationships((nitro, "DEPLOYS", correlation_qatar_tld), (TIP131000003, "CREATE_SIGNATURE", correlation_qatar_tld, {"date" : 20131019}), (TIP131000003, "ATTRIBUTION", sea, {"confidence":100}))


#Indicators/Events Originating to Scenario INC131000001

INC131000001 = graph_db.get_or_create_indexed_node("incs", "inc", "INC131000001", {"inc": "INC131000001", "tlp" : "red", "blocked": "true", "exfil": "false", "notes": "Analyst Notes on IR of this incident go here", "attached_files": ["path/to/file/one","path/to/file/two"], "date": 20131008})
INC131000001["status"] = "open"

PHS20131000001 = graph_db.get_or_create_indexed_node("phishes", "phish", "PHS20131000001", {"phish": "PHS20131000001", "subject": "2013 Conference Invite", "x-mailer": "blah blach outlook.3k2", "headers": "headers go here", "body":"body goes here", "attachments": ['03557c3e5c87e6a121c58f664b0ebf18']})

blackcake_net = graph_db.get_or_create_indexed_node("domains", "domain", "blackcake.net", {"domain":"blackcake.net", "registrant_email":"BLACKCAKE.NET@domainsbyproxy.com", "blocked_out": "true", "sinkholed":"false", "whitelist":"false"})

INC1_delivery_baddoc_doc = graph_db.get_or_create_indexed_node("hashes", "hash", "eddf6ff5b38a103389874d4801184e27", {"hash":"eddf6ff5b38a103389874d4801184e27", "filename":"baddoc.doc", "automal" : "relevant results from sandbox go here", "malicious" : "true", "blacklisted":"true"})

INC1_dropped_dropped_exe = graph_db.get_or_create_indexed_node("hashes", "hash", "03557c3e5c87e6a121c58f664b0ebf18", {"hash":"03557c3e5c87e6a121c58f664b0ebf18", "filename":"dropped.exe", "automal" : "relevant results from sandbox go here", "malicious" : "true", "blacklisted":"true"})

SNK112 = graph_db.get_or_create_indexed_node("service_tickets", "service_ticket", "SNK112", {"service_ticket":"SNK112", "type":"dns sinkhole", "status":"open"})

#Indicators/Events Originating to Scenario INC131000002
INC131000002 = graph_db.get_or_create_indexed_node("incs", "inc", "INC131000002", {"inc": "INC131000002", "tlp" : "red", "blocked": "true", "exfil": "false", "notes": "InfoSec Analyst (Chris Daniels) Checking status of compromised domains", "attached_files": ["path/to/file/one","path/to/file/two"], "date": 20131020})
INC131000002["status"] = "closed"
graph_db.get_or_create_relationships((INC131000002, "DELIVERY", google_qa), (INC131000002, "DELIVERY", facebook_qa), (correlation_qatar_tld, "ALERT", INC131000002, {"date" : 20131020}), (correlation_qatar_tld, "DETECTS", google_qa), (correlation_qatar_tld, "DETECTS", facebook_qa), (VRZ398BB, "VISITS", facebook_qa, {"date": 20131020}), (VRZ398BB, "VISITS", google_qa, {"date": 20131020}))

#Indicators/Events Originating to Scenario INC131000003

#Indicators/Events Originating to Scenario INC131000004

#Indicators/Events Originating to Scenario INC131000005



#Relationships

rels = graph_db.get_or_create_relationships(
	(INC1_dropped_dropped_exe, "C2", mantech_blackcake_net, {"port": 443}), 
	(INC1_delivery_baddoc_doc, "DROPPED", INC1_dropped_dropped_exe),
	(INC1_delivery_baddoc_doc, "EXPLOITS", CVE_2012_0158),
	(cf_rtf_cve_2012_0158_var1_objocx, "DETECTS", CVE_2012_0158),
	(win_troj_apt_greencat_c2, "DETECTS", INC1_dropped_dropped_exe),
	(mirscan_malicious_files, "DETECTS", INC1_dropped_dropped_exe),
	(correlation_malicious_senders, "DETECTS", webc2_phisher),
	(correlation_malicious_ips, "DETECTS", ip212125200204),
	(correlation_malicious_ips, "DETECTS", ip77777777),
	(correlation_malicious_domains, "DETECTS", blackcake_net),
	(correlation_malicious_domains, "DETECTS", mantech_blackcake_net),
	(correlation_malicious_senders, "ALERT", INC131000001, {"date":20131008}),
	(nitro, "DEPLOYS", correlation_malicious_domains),
	(nitro, "DEPLOYS", correlation_malicious_ips),
	(nitro, "DEPLOYS", correlation_malicious_senders),
	(uglymonkey, "ASSOCIATED", webc2, {"confidence": 90}),
	(pownyou2, "ASSOCIATED", webc2, {"confidence": 80}),
	(sourcefire, "DEPLOYS", win_troj_apt_greencat_c2),
	(fireeye, "DEPLOYS", cf_rtf_cve_2012_0158_var1_objocx),
	(damballa, "DEPLOYS", correlation_malicious_ips),
	(paloalto, "DEPLOYS", correlation_malicious_domains),
	(mir, "SCANS_FOR", mirscan_malicious_files, {"date" : 20131008}),
	(blackcake_net, "RESOLVES_TO", ip77777777,  {"date" : 20131007}),
	(ip77777777, "HOSTS", blackcake_net, {"date" : 20131007}),
	(mantech_blackcake_net, "RESOLVES_TO", ip212125200204, {"date" : 20131007}),
	(mantech_blackcake_net, "SUBDOMAIN_OF", blackcake_net),
	(ip212125200204, "HOSTS", mantech_blackcake_net, {"date" : 20131007}),
	(ip20985216176, "SENDING_IP", PHS20131000001),
	(PHS20131000001, "ATTACHMENT", INC1_delivery_baddoc_doc),
	(PHS20131000001, "FROM", webc2_phisher),
	(INC131000001, "DELIVERY", PHS20131000001),
	(TIP131000001, "SENDER", webc2_phisher),
	(TIP131000001, "ATTRIBUTION", webc2, {"confidence": 90}),
	(TIP131000001, "BLOCK_TICKET_CREATE", BLK111, {"date" : 20131007}),
	(TIP131000001, "SINKHOLE_TICKET_CREATE", SNK111, {"date" : 20131007}),
	(TIP131000001, "C2", ip212125200204, {"port": 443}),
	(webc2_phisher, "EMAIL_DOMAIN", gmail_com),
	(gmail_com, "RESOLVES_TO", ip20985216176, {"date" : 20131007}),
	(ip20985216176, "HOSTS", gmail_com, {"date" : 20131007}),
	(BLK111, "BLOCK",ip77777777, {"date" : 20131007}),
	(BLK111, "BLOCK",ip212125200204, {"date" : 20131007}),
	(SNK111, "SINKHOLE", mantech_blackcake_net, {"date" : 20131007}),
	(SNK112, "SINKHOLE", blackcake_net, {"date" : 20131008}),
	(INC131000001, "SINKHOLE_TICKET_CREATE", SNK112, {"date" : 20131008}),
	(PHS20131000001, "TARGET", bhayes, {"date" : 20131008}),
	(PHS20131000001, "TARGET", lmassey, {"date" : 20131008}),
	(PHS20131000001, "TARGET", ddaniels, {"date" : 20131008}),
	(bhayes, "USES", VRZ3984827),
	(bhayes, "USES_ADMIN", VRZ3984827),
	(bhayes, "USES", VRZ398ES),
	(lmassey, "USES", VRZ398BB),
	(ddaniels, "USES", VRZ398BB),
	(ddaniels, "USES", VRZ3984827),
	(ddaniels, "REPORTS_TO", lmassey),
	(kpoole, "REPORTS_TO", bhayes),
	(lmassey, "REPORTS_TO", bhayes),
	(ggreene, "REPORTS_TO", bhayes),
	(lcolon,"REPORTS_TO", kpoole),
	(bhayes, "REPORTS_TO", sbennett),
	(bhayes, "MEMBER_OF", office_cso),
	(lmassey, "MEMBER_OF", office_cso),
	(ddaniels, "MEMBER_OF", office_cso),
	(sbennett, "MEMBER_OF", executives),
	(ggreene, "MEMBER_OF", office_cso),
	(lcolon, "MEMBER_OF", sec_ops),
	(kpoole, "MEMBER_OF", sec_ops),
	(bhayes, "WORKS_AT", washington_dc),
	(lmassey, "WORKS_AT", washington_dc),
	(ddaniels, "WORKS_AT", washington_dc),
	(kpoole, "WORKS_AT", washington_dc),
	(ggreene, "WORKS_AT", sanfrancisco_ca),
	(lcolon, "WORKS_AT", sanfrancisco_ca),
	(sbennett, "WORKS_AT", washington_dc)

)

