import regex,os,csv,sys,stdiomask,time,argparse,configparser
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPCursorError

#Grab the scriptName so it can be used to name the output files.
#This accomodates a compiled or un-compiled script.
if getattr(sys, 'frozen', False):
    # frozen
    scriptName=os.path.basename(sys.executable)
    scriptName=scriptName.rstrip('.exe')
else:
    #not frozen
    base=os.path.basename(__file__)
    os.path.splitext(base)
    scriptName=os.path.splitext(base)[0]

dts0=time.strftime('%Y%m%d_%H%M%S', time.localtime(time.time()))

#Global declarations
userList=[]
groupPathList=[]
groupMapDict={}
groupRootList=[]
domainsConnDict={}
domainSam2Fqdn={}
domainSam2Dn={}
domainFqdn2Sam={}
domainDNx=[]

#This is a regex used by the groupMembersDump function to break up the dn into CN, Path, and DCs.
px1=regex.compile('^(?:(?<cn>CN=(?<name>[^,]*)),)?(?:(?<path>(?:(?:CN|OU)=[^,]+,?)+),)?(?<domain>(?:DC=[^,]+,?)+)$')
#This regex is also used by groupMembersDump to grab the domain (first item in the DC part)
px2=regex.compile('^DC=(.*?),')
#Pulls the hostname from the FQDN
px3=regex.compile('(^[^.]*)')

#Create file outputs
outputFN0=scriptName+'_output0-'+dts0+'.csv'
outputFH0=open(outputFN0,'w',newline='',encoding='utf-8')
writer0=csv.writer(outputFH0, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
writer0.writerow(['rootGroup','path','leafGroup','user'])
debugFN0=scriptName+'_debug0-'+dts0+'.txt'
debugFH0 = open(debugFN0,"w+")

#Get interactive windows user and set credentials
domain_name = os.environ.get('userdomain')
user_name = os.environ.get('username')
user1='{}\\{}'.format(domain_name, user_name)
print('*******************************************************************************')
print('User:',user1)
password = stdiomask.getpass()
print('*******************************************************************************')

#Define the domains by FQDN, read from ini file.
#The ini file has one section, 'domains', with one value 'fqdns' that is set to a comma delimited list of fqdns for the forest. Any quotes, single or doulbe, in the list will be striped out.
iniFN0=scriptName+'.ini'
config = configparser.ConfigParser()
config.sections()
config.read(iniFN0)
fqdns=config['domains']['fqdns']
fqdns=fqdns.replace('\'','')
fqdns=fqdns.replace('\"','')
#convert string to list
domainsFqdnList=fqdns.split(',')

#Command line argument processing
parser = argparse.ArgumentParser()
parser.add_argument("--targetdomain","-td",required=True,default='') #Target domain in as SamName or FQDN
args = parser.parse_args()
argsDict=vars(args)
#print(argsDict)
print('Target Domain=',args.targetdomain)
print('Forest Domains From INI File:',iniFN0)
for domain in domainsFqdnList:
    print('\t'+domain)
print('*******************************************************************************')

#sys.exit()

def main():
    #Call domain indexes creation function
    indexDomains(domainsFqdnList,domainSam2Fqdn,domainFqdn2Sam,domainSam2Dn)

    #Check to make sure that target domain is in the domain list.
    if args.targetdomain in domainSam2Fqdn.keys():
        #Target domain provided as SamName
        targetDomainSam=args.targetdomain
        targetDomainFqdn=domainSam2Fqdn[targetDomainSam]
        targetDomainDN=domainSam2Dn[targetDomainSam]
    elif args.targetdomain in domainFqdn2Sam.keys():
        #Target domain provided as Fqdn
        targetDomainFqdn=args.targetdomain
        targetDomainSam=domainFqdn2Sam[targetDomainFqdn]
        targetDomainDN=domainSam2Dn[targetDomainFqdn]
    else:
        print('!!!ERROR!!! - Target domain not in domain list')
        sys.exit()

    #print('targetDomainFqdn=',targetDomainFqdn)
    #print('targetDomainDN=',targetDomainDN)

    #Make the connection for each domain and store as a domain/connection dict.
    print('Establishing connections to all Forest Domains')
    for domain in domainsFqdnList:
        print('\t'+'connecting to domain->',domain)
        domainsConnDict[domain]=Connection(Server(domain, get_info=ALL,allowed_referral_hosts=[('*', True)]), user=user1, password=password, authentication=NTLM, auto_bind=True,raise_exceptions=False)

    #for domain in domainsConnDict.keys():
        #print('domain=',domain)
        #print('domain_connection=',domainsConnDict[domain])

    print('*******************************************************************************')

    #Creates the initial group list from a generator. This is done so it can be dealt with as a list.
    results0=list(domainsConnDict[targetDomainFqdn].extend.standard.paged_search(search_base=targetDomainDN, search_filter='(&(objectclass=group)(objectcategory=group)(|(groupType=-2147483640)(groupType=-2147483643)(groupType=-2147483644)(groupType=-2147483646)))', attributes=['cn','samAccountName','samAccountType','description','groupType','instanceType','member','whenCreated','whenChanged','distinguishedname']))

    #Remove first element as this is just a header for the result.
    del results0[0]

    #Set up this initial group list from the initial group search.
    #This just listifys the ldap search result and gets the name into "domainName\groupName".
    #This is just the creation of the tope level list of groups for the target domain to be enumerated.
    #rowDict in tqdm(destinationIPsDict, total=len(list(destinationIPsDict)), unit=':destinationIPs'):
    for group0 in results0:
        samAccountName=group0['attributes']['samAccountName']
        group1='{}\\{}'.format(targetDomainSam,samAccountName)
        groupRootList.append(group1)

    groupRootListLen=len(groupRootList)
    #This takes the list from the previous step and drills down on each entry. When it finds a new nested group it adds it to the stack to be drilled.
    i=0
    for groupRootx in groupRootList:
        i=i+1
        progress=str(i)+' of '+str(groupRootListLen)+' total groups'
        print('\t'+'Processing Root Group-> '+'"'+groupRootx+'"'+' -> '+progress )
        #split the item into "groupDomain" and "groupSameAccountName"
        #UV groupDomain,groupSamAccountName=groupRootx.split('\\')
        #Set the groupPathList
        groupPathList=[{groupRootx:''}]

        #Foreach item in the "groupPathList", drill down the membership until there are no more nested groups.
        for item in groupPathList:
            group,path=item.popitem()
            groupMembersDump(groupRootx,groupPathList,group,path)

##Creates lookup indexes for domain Fqdn, SamName, and DN
def indexDomains(domainsFqdnList,domainSam2Fqdn,domainFqdn2Sam,domainSam2Dn):
    for domain in domainsFqdnList:
        mx3=px3.match(domain)
        samDomainName=mx3.group(1)
        domainSam2Fqdn[samDomainName]=domain
        domainFqdn2Sam[domain]=samDomainName
        partsList=domain.split('.')
        domainDN=','
        domainDNx=[]
        for part in partsList:
            partx='DC='+part
            #print('partx=',partx)
            domainDNx.append(partx)
            
        #print('domainDNx=',domainDNx)
        domainDN=domainDN.join(domainDNx)
        domainSam2Dn[samDomainName]=domainDN

        #print('domainSam2Fqdn=',domainSam2Fqdn[samDomainName])
        #print('domainFqdn2Sam=',domainFqdn2Sam[domain])
        #print('domainSam2Dn=',domainSam2Dn[samDomainName])

#This function does the group membership drill down, if a user is found it's tabulated, if a group is found it's feed back to the stack of groups to be drilled but the path is attached to it so where it came from can be tracked.
def groupMembersDump(groupRoot,groupPathList,groupx,pathx):
    groupDomain,groupSamAccountName=groupx.split('\\')
    #print('groupMembersDump - Processing->',groupx)

    connGroup=domainsConnDict[domainSam2Fqdn[groupDomain]]
    groupDomainDN=domainSam2Dn[groupDomain]

    searchx="(&(objectclass=group)(objectcategory=group)(samAccountName={}))".format(groupSamAccountName)
    connGroup.search(search_base=groupDomainDN, search_filter=searchx, attributes=['cn','samAccountName','samAccountType','description','groupType','member','distinguishedname'])
    connGroupEntriesObj=connGroup.entries

    for entry in connGroupEntriesObj:
        for memberx in entry.member.values:
            mx1=px1.match(memberx)
            memberDomainDN=mx1.group('domain')
            mx2=px2.match(memberDomainDN)
            memberDomain=mx2.group(1)
            #Set conn to gropu members domain.
            connMember=domainsConnDict[domainSam2Fqdn[memberDomain]]
            #Replace characters that cause errors.
            memberx=memberx.replace('(','\\28')
            memberx=memberx.replace(')','\\29')
            memberx=memberx.replace('\\','\\5c')
            #Grab group member object.
            connMember.search(search_base=memberDomainDN,search_scope=SUBTREE,search_filter=f'(distinguishedName={memberx})',attributes=['samAccountName','objectCategory','objectClass','samAccountType'])
            #Pull out group members attributes.
            samAccountName=connMember.response[0]['attributes']['samAccountName']
            #objectCategory=connMember.response[0]['attributes']['objectCategory']
            samAccountType=connMember.response[0]['attributes']['samAccountType']
            #objectClass=connMember.response[0]['attributes']['objectClass']

            #Evaluate member type group vs user
            if samAccountType==805306368: #user
                #End of the line, write this user out to the output file.
                pathx1=pathx+':'+groupx
                userMember='{}\\{}'.format(memberDomain,samAccountName)
                #print(groupRoot,',',pathx1,',',groupx,',',userMember)
                writer0.writerow([groupRoot,pathx1,groupx,userMember])
                #print('User Member Found:',groupx,'->',userMember)    
            elif samAccountType==268435456 or samAccountType==536870912: #Group
                #Add this group to the stack for additional drill down.
                groupMember='{}\\{}'.format(memberDomain,samAccountName)
                #print('Group Memeber Found:',groupx,'->',groupMember)
                #groupList.append(groupMember) # recurse
                #Add to groupPathDict
                pathx1=pathx+':'+groupx
                #print('pathx1=',pathx1)
                #print('groupPathList=',groupPathList)
                groupPathList.append({groupMember:pathx1})
                #print('groupPathList*=',groupPathList)
            else:
                debugStr0='!ERROR!-Unknown samAcccountType:'+'groupx='+str(groupx)
                debugStr1='samAccountName='+str(samAccountName)+', samAccountType='+str(samAccountType)+', dn='+str(memberx)
                #print(debugStr0)
                #print(debugStr1)
                debugFH0.write(debugStr0+"\n")
                debugFH0.write(debugStr1+"\n")


if __name__ == '__main__':
    main()
    
