# Demo2022

Topology

![image](https://user-images.githubusercontent.com/63335518/154074462-13488089-8fe7-4077-b1d5-fe56eb776170.png)

Назначение имен хостов и адресов

#RTR-L cisco

```
en

conf t

hostname RTR-L

int gi 1

ip address 4.4.4.100 255.255.255.0

no sh

int gi 2

ip address 192.168.100.254 255.255.255.0

no sh

end

wr
```
#RTR-R cisco
```
en

conf t

hostname RTR-R

int gi 1

ip address 5.5.5.100 255.255.255.0

no sh

int gi 2

ip address 172.16.100.254 255.255.255.0

no sh

end

wr
```

#SRV windows server
Powershell
```
Rename-Computer -NewName SRV

$GetIndex = Get-NetAdapter
New-NetIPAddress -InterfaceIndex $GetIndex.ifIndex -IPAddress 192.168.100.200 -PrefixLength 24 -DefaultGateway 192.168.100.254
Set-DnsClientServerAddress -InterfaceIndex $GetIndex.ifIndex -ServerAddresses ("192.168.100.200","4.4.4.1")

Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Any
```

#WEB-L linux
```
hostnamectl set-hostname WEB-L

apt-cdrom add
apt install -y network-manager

nmcli connection show
nmcli connection modify Wired\ connection\ 1 conn.autoconnect yes conn.interface-name ens192 ipv4.method manual ipv4.addresses '192.168.100.100/24' ipv4.dns 192.168.100.200 ipv4.gateway 192.168.100.254
```

#WEB-R linux
```
hostnamectl set-hostname WEB-R

apt-cdrom add
apt install -y network-manager

nmcli connection show
nmcli connection modify Wired\ connection\ 1 conn.autoconnect yes conn.interface-name ens192 ipv4.method manual ipv4.addresses '172.16.100.100/24' ipv4.dns 192.168.100.200 ipv4.gateway 172.16.100.254
```

#ISP linux
```
hostnamectl set-hostname ISP

apt-cdrom add
apt install -y network-manager bind9 chrony 

nmcli connection show

nmcli connection modify Wired\ connection\ 1 conn.autoconnect yes conn.interface-name ens192 ipv4.method manual ipv4.addresses '3.3.3.1/24'
nmcli connection modify Wired\ connection\ 2 conn.autoconnect yes conn.interface-name ens224 ipv4.method manual ipv4.addresses '4.4.4.1/24'
nmcli connection modify Wired\ connection\ 3 conn.autoconnect yes conn.interface-name ens256 ipv4.method manual ipv4.addresses '5.5.5.1/24'
```
#CLI windows
Powershell
```Rename-Computer -NewName CLI

$GetIndex = Get-NetAdapter
New-NetIPAddress -InterfaceIndex $GetIndex.ifIndex -IPAddress 3.3.3.10 -PrefixLength 24 -DefaultGateway 3.3.3.1
Set-DnsClientServerAddress -InterfaceIndex $GetIndex.ifIndex -ServerAddresses ("3.3.3.1")
```

Сетевая связность

#ISP forward 
```
  nano /etc/sysctl.conf 
  net.ipv4.ip_forward=1
  sysctl -p 
  ```
RTR-L Last resort gateway
``` 
ip route 0.0.0.0 0.0.0.0 4.4.4.1 
```
RTR-R Last resort gateway
```
ip route 0.0.0.0 0.0.0.0 5.5.5.1
```
RTR-L NAT
```
int gi 1
ip nat outside
!
int gi 2
ip nat inside
!
access-list 1 permit 192.168.100.0 0.0.0.255
ip nat inside source list 1 interface Gi1 overload
```
RTR-R NAT
```
int gi 1
ip nat outside
!
int gi 2
ip nat inside
!
access-list 1 permit 172.16.100.0 0.0.0.255
ip nat inside source list 1 interface Gi1 overload
```
RTR-L Tunnel + eigrp
```
interface Tunnel 1
ip address 172.16.1.1 255.255.255.0
tunnel mode gre ip
tunnel source 4.4.4.100
tunnel destination 5.5.5.100

router eigrp 6500
network 192.168.100.0 0.0.0.255
network 172.16.1.0 0.0.0.255
```
RTR-R Tunnel + eigrp
```
interface Tunnel 1
ip address 172.16.1.2 255.255.255.0
tunnel mode gre ip
tunnel source 5.5.5.100
tunnel destination 4.4.4.100

router eigrp 6500
network 172.16.100.0 0.0.0.255
network 172.16.1.0 0.0.0.255
```
RTR-L IPsec
```
crypto isakmp policy 1
encr aes
authentication pre-share
hash sha256
group 14
!
crypto isakmp key TheSecretMustBeAtLeast13bytes address 5.5.5.100
crypto isakmp nat keepalive 5
!
crypto ipsec transform-set TSET  esp-aes 256 esp-sha256-hmac
mode tunnel
!
crypto ipsec profile VTI
set transform-set TSET

interface Tunnel1
tunnel mode ipsec ipv4
tunnel protection ipsec profile VTI
```

RTR-R IPSec
```
conf t

crypto isakmp policy 1
encr aes
authentication pre-share
hash sha256
group 14
!
crypto isakmp key TheSecretMustBeAtLeast13bytes address 4.4.4.100
crypto isakmp nat keepalive 5
!
crypto ipsec transform-set TSET  esp-aes 256 esp-sha256-hmac
mode tunnel
!
crypto ipsec profile VTI
set transform-set TSET

interface Tunnel1
tunnel mode ipsec ipv4
tunnel protection ipsec profile VTI
```
RTR-L ACL
```
ip access-list extended Lnew

permit tcp any any established
permit udp any host 4.4.4.100 eq 53
permit tcp any host 4.4.4.100 eq 53
permit udp host 5.5.5.1 eq 123 any
permit tcp any host 4.4.4.100 eq 80 
permit tcp any host 4.4.4.100 eq 443 
permit tcp any host 4.4.4.100 eq 2222 
permit udp host 5.5.5.100 host 4.4.4.100 eq 500
permit esp any any
permit icmp any any

int gi 1 
ip access-group Lnew in
```
RTR-R ACL
```
ip access-list extended Rnew

permit tcp any any established
permit tcp any host 5.5.5.100 eq 80 
permit tcp any host 5.5.5.100 eq 443 
permit tcp any host 5.5.5.100 eq 2244 
permit udp host 4.4.4.100 host 5.5.5.100 eq 500
permit esp any any
permit icmp any any

int gi 1 
ip access-group Rnew in
```
DNAT RTR-L
```
ip nat inside source static tcp 192.168.100.100 22 4.4.4.100 2222
```
DNAT RTR-R
```
ip nat inside source static tcp 172.16.100.100 22 5.5.5.100 2244
```
SSH WEB-L
```
apt-cdrom add
apt install -y openssh-server ssh

systemctl start sshd
systemctl enable ssh
```
SSH WEB-R
```
apt-cdrom add
apt install -y openssh-server ssh

systemctl start sshd
systemctl enable ssh
```

Приложения

ISP DNS
```
apt-cdrom add
apt install -y bind9
```
```
mkdir /opt/dns
cp /etc/bind/db.local /opt/dns/demo.db
chown -R bind:bind /opt/dns
```
```
nano /etc/apparmor.d/usr.sbin.named
```
```
/opt/dns/** rw,
```
![image](https://user-images.githubusercontent.com/63335518/156514445-3f281371-a3aa-4446-9784-b15acf194e23.png)
```
systemctl restart apparmor.service
```
```
nano /etc/bind/named.conf.options
```
![image](https://user-images.githubusercontent.com/63335518/156514605-1537f26d-a5b1-41c1-a43c-fd7f6f220af3.png)
```
nano /etc/bind/named.conf.default-zones
```
```
zone "demo.wsr" {
   type master;
   allow-transfer { any; };
   file "/opt/dns/demo.db";
};
```
![image](https://user-images.githubusercontent.com/63335518/156514669-c7190c09-8b80-4a34-a2a9-246d300f6b9c.png)
```
nano /opt/dns/demo.db
```
```
@ IN SOA demo.wsr. root.demo.wsr.(
```
```
@ IN NS isp.demo.wsr.
isp IN A 3.3.3.1
www IN A 4.4.4.100
www IN A 5.5.5.100
internet CNAME isp.demo.wsr.
int IN NS rtr-l.demo.wsr.
rtr-l IN  A 4.4.4.100
```
![image](https://user-images.githubusercontent.com/63335518/156514732-b9d4a221-bc1a-415f-bea8-727b6c2e0c9a.png)
```
systemctl restart bind9
```
SRV DNS
```
Install-WindowsFeature -Name DNS -IncludeManagementTools
Add-DnsServerPrimaryZone -Name "int.demo.wsr" -ZoneFile "int.demo.wsr.dns"
Add-DnsServerPrimaryZone -NetworkId 192.168.100.0/24 -ZoneFile "int.demo.wsr.dns"
Add-DnsServerPrimaryZone -NetworkId 172.16.100.0/24 -ZoneFile "int.demo.wsr.dns"

Add-DnsServerResourceRecordA -Name "web-l" -ZoneName "int.demo.wsr" -AllowUpdateAny -IPv4Address "192.168.100.100" -CreatePtr 
Add-DnsServerResourceRecordA -Name "web-r" -ZoneName "int.demo.wsr" -AllowUpdateAny -IPv4Address "172.16.100.100" -CreatePtr 
Add-DnsServerResourceRecordA -Name "srv" -ZoneName "int.demo.wsr" -AllowUpdateAny -IPv4Address "192.168.100.200" -CreatePtr 
Add-DnsServerResourceRecordA -Name "rtr-l" -ZoneName "int.demo.wsr" -AllowUpdateAny -IPv4Address "192.168.100.254" -CreatePtr 
Add-DnsServerResourceRecordA -Name "rtr-r" -ZoneName "int.demo.wsr" -AllowUpdateAny -IPv4Address "172.16.100.254" -CreatePtr 

Add-DnsServerResourceRecordCName -Name "webapp1" -HostNameAlias "web-l.int.demo.wsr" -ZoneName "int.demo.wsr"
Add-DnsServerResourceRecordCName -Name "webapp2" -HostNameAlias "web-r.int.demo.wsr" -ZoneName "int.demo.wsr"
Add-DnsServerResourceRecordCName -Name "ntp" -HostNameAlias "srv.int.demo.wsr" -ZoneName "int.demo.wsr"
Add-DnsServerResourceRecordCName -Name "dns" -HostNameAlias "srv.int.demo.wsr" -ZoneName "int.demo.wsr"
```
ISP NTP
```
apt install -y chrony 
```
```
nano /etc/chrony/chrony.conf
```
```
local stratum 4
allow 4.4.4.0/24
allow 3.3.3.0/24
```
![image](https://user-images.githubusercontent.com/63335518/156515040-6f73fa90-80ee-4cb1-8665-c6cf865b6318.png)
```
systemctl restart chronyd
```
SRV NTP
```
New-NetFirewallRule -DisplayName "NTP" -Direction Inbound -LocalPort 123 -Protocol UDP -Action Allow
w32tm /query /status
Start-Service W32Time
w32tm /config /manualpeerlist:4.4.4.1 /syncfromflags:manual /reliable:yes /update
Restart-Service W32Time
```
CLI NTP
```
New-NetFirewallRule -DisplayName "NTP" -Direction Inbound -LocalPort 123 -Protocol UDP -Action Allow
Start-Service W32Time
w32tm /config /manualpeerlist:4.4.4.1 /syncfromflags:manual /reliable:yes /update
Restart-Service W32Time
Set-Service -Name W32Time -StartupType Automatic
```
RTR-L NTP
```
en
conf t
ip domain name int.demo.wsr
ip name-server 192.168.100.200
ntp server ntp.int.demo.wsr
```
RTR-R NTP
```
en
conf t
ip domain name int.demo.wsr
ip name-server 192.168.100.200
ntp server ntp.int.demo.wsr
```
Web-L NTP
```
apt-cdrom add
apt install -y chrony 
```
```
nano /etc/chrony/chrony.conf
```
```
pool ntp.int.demo.wsr iburst
allow 192.168.100.0/24
```
![image](https://user-images.githubusercontent.com/63335518/156515326-049de990-dc45-4dda-a465-74ca6959defa.png)

```
systemctl restart chrony
```

Web-R NTP
```
apt-cdrom add
apt install -y chrony 
```
```
nano /etc/chrony/chrony.conf
```
```
pool ntp.int.demo.wsr iburst
allow 192.168.100.0/24
```
![image](https://user-images.githubusercontent.com/63335518/156515397-8e05ca71-ce58-4620-b1a0-62f464a6404b.png)
```
systemctl restart chrony
```
SRV Самба туц туц

Srv raid 1
```
get-disk
set-disk -Number 1 -IsOffline $false
set-disk -Number 2 -IsOffline $false
```
```
New-StoragePool -FriendlyName "POOLRAID1" -StorageSubsystemFriendlyName "Windows Storage*" -PhysicalDisks (Get-PhysicalDisk -CanPool $true)
New-VirtualDisk -StoragePoolFriendlyName "POOLRAID1" -FriendlyName "RAID1" -ResiliencySettingName Mirror -UseMaximumSize
Initialize-Disk -FriendlyName "RAID1"
New-Partition -DiskNumber 3 -UseMaximumSize -DriveLetter R
Format-Volume -DriveLetter R
```
SRV Самба айц айц
```
Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools
New-Item -Path R:\storage -ItemType Directory
New-SmbShare -Name "SMB" -Path "R:\storage" -FullAccess "Everyone"
```
CLI SMB Web-L + Web-R
Web-L SMB
```
apt-cdrom add
apt install -y cifs-utils
```
```
nano /root/.smbclient
```
```
username=Administrator
password=Pa$$w0rd
```
```
nano /etc/fstab
```
```
//srv.int.demo.wsr/smb /opt/share cifs user,rw,_netdev,credentials=/root/.smbclient 0 0
```
```
mkdir /opt/share
mount -a
```
Web-R SMB
```
apt-cdrom add
apt install -y cifs-utils
```
```
nano /root/.smbclient
```
```
username=Administrator
password=Pa$$w0rd
```
```
nano /etc/fstab
```
```
//srv.int.demo.wsr/smb /opt/share cifs user,rw,_netdev,credentials=/root/.smbclient 0 0
```
```
mkdir /opt/share
mount -a
```
SRV ADCS
```
Install-WindowsFeature -Name AD-Certificate, ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType StandaloneRootCa -CACommonName "Demo.wsr" -force
Install-AdcsWebEnrollment -Confirm -force
New-SelfSignedCertificate -subject "localhost" 
Get-ChildItem cert:\LocalMachine\My
Move-item Cert:\LocalMachine\My\XFX2DX02779XFD1F6F4X8435A5X26ED2X8DEFX95 -destination Cert:\LocalMachine\Webhosting\
New-IISSiteBinding -Name 'Default Web Site' -BindingInformation "*:443:" -Protocol https -CertificateThumbPrint XFX2DX02779XFD1F6F4X8435A5X26ED2X8DEFX95 
Start-WebSite -Name "Default Web Site"
Get-CACrlDistributionPoint | Remove-CACrlDistributionPoint -force
Get-CAAuthorityInformationAccess |Remove-CAAuthorityInformationAccess -force
Restart-Service CertSrc
```
Web-приложения
Web-L Docker
```
apt-cdrom add
```
```
apt install -y docker-ce
systemctl start docker
systemctl enable docker
```
```
mkdir /mnt/app
```
```
mount /dev/sr0 /mnt/app
```
```
docker load < /mnt/app/app.tar
```
```
docker images
docker run --name app  -p 8080:80 -d app
docker ps
```
Web-R Docker
```
apt-cdrom add
```
```
apt install -y docker-ce
systemctl start docker
systemctl enable docker
```
```
mkdir /mnt/app
```
```
mount /dev/sr0 /mnt/app
```
```
docker load < /mnt/app/app.tar
```
```
docker images
docker run --name app  -p 8080:80 -d app
docker ps
```
RTR-L
```
en
conf t
no ip http secure-server
wr
reload
```
```
ip nat inside source static tcp 192.168.100.100 80 4.4.4.100 80 
ip nat inside source static tcp 192.168.100.100 443 4.4.4.100 443 
```
RTR-R
```
en
conf t
no ip http secure-server
wr
reload
```
```
ip nat inside source static tcp 172.16.100.100 80 5.5.5.100 80 
ip nat inside source static tcp 172.16.100.100 443 5.5.5.100 443 
```
SRV ssl
![image](https://user-images.githubusercontent.com/63335518/156516504-860a0fe1-b6d0-42c9-aacc-b11e68e96d0f.png)
![image](https://user-images.githubusercontent.com/63335518/156516525-0957d57d-70ed-4468-a2ad-fbdb6fa448b5.png)
![image](https://user-images.githubusercontent.com/63335518/156516533-62a4f346-f2d3-4423-9e8d-2afe0e832971.png)
![image](https://user-images.githubusercontent.com/63335518/156516546-06bc7544-f3c3-41e0-8be1-464d6df5d6e0.png)
![image](https://user-images.githubusercontent.com/63335518/156516555-e9fd6912-91fa-45e8-b63b-c10786354867.png)
![image](https://user-images.githubusercontent.com/63335518/156516568-71f11b5f-104f-472d-a021-a46fc52579d0.png)
![image](https://user-images.githubusercontent.com/63335518/156516642-8835c24e-fb83-4be6-a59b-248b8197e773.png)
![image](https://user-images.githubusercontent.com/63335518/156516663-fa15aaf6-c4af-4fa9-9a47-a2ab8653a368.png)
![image](https://user-images.githubusercontent.com/63335518/156516669-9443f901-eda9-4fa0-823e-b73ce9b104fe.png)
![image](https://user-images.githubusercontent.com/63335518/156516677-a58e6e38-613b-47b3-8ac3-a0d74421f319.png)
![image](https://user-images.githubusercontent.com/63335518/156516687-746b263e-e160-4f38-8a15-7c1d30c9a830.png)

Web-L ssl
```
apt install -y nginx
```
```
cd /opt/share
```
```
openssl pkcs12 -nodes -nocerts -in www.pfx -out www.key

openssl pkcs12 -nodes -nokeys -in www.pfx -out www.cer
```
```
cp /opt/share/www.key /etc/nginx/www.key

cp /opt/share/www.cer /etc/nginx/www.cer
```
```
nano /etc/nginx/snippets/snakeoil.conf
```
![image](https://user-images.githubusercontent.com/63335518/156516846-a81a91e5-9959-4ff2-9948-a99e7a12db25.png)
```
nano /etc/nginx/sites-available/default
```
```
upstream backend { 
 server 192.168.100.100:8080 fail_timeout=25; 
 server 172.16.100.100:8080 fail_timeout=25; 
} 
 
server { 
    listen 443 ssl default_server; 
    include /etc/ngnix/snippets/snakeoil.conf;

    server_name www.demo.wsr; 

 location / { 
  proxy_pass http://backend ;
 } 
}

server { 
   listen 80  default_server; 
  server_name _; 
  return 301 https://www.demo.wsr;

}
```
```
systemctl reload nginx
```
Web-R ssl
```
apt install -y nginx
```
```
cd /opt/share
```
```
openssl pkcs12 -nodes -nocerts -in www.pfx -out www.key

openssl pkcs12 -nodes -nokeys -in www.pfx -out www.cer
```
```
cp /opt/share/www.key /etc/nginx/www.key
cp /opt/share/www.cer /etc/nginx/www.cer
```
```
nano /etc/nginx/snippets/snakeoil.conf
```
![image](https://user-images.githubusercontent.com/63335518/156516846-a81a91e5-9959-4ff2-9948-a99e7a12db25.png)
```
nano /etc/nginx/sites-available/default
```
```
upstream backend { 
 server 192.168.100.100:8080 fail_timeout=25; 
 server 172.16.100.100:8080 fail_timeout=25; 
} 
 
server { 
    listen 443 ssl default_server; 
    include /etc/ngnix/snippets/snakeoil.conf;

    server_name www.demo.wsr; 

 location / { 
  proxy_pass http://backend ;
 } 
}

server { 
   listen 80  default_server; 
  server_name _; 
  return 301 https://www.demo.wsr;

}
```
```
systemctl reload nginx
```
CLI ssl
```
scp -P 2244 'root@5.5.5.100:/opt/share/ca.cer' C:\Users\user\Desktop\
```
![image](https://user-images.githubusercontent.com/63335518/156727841-c17c654c-3694-49fc-b579-51427f310f8c.png)

![image](https://user-images.githubusercontent.com/63335518/156727978-cb5b8e59-3ac4-47eb-b2cf-312cd8dd9e4a.png)
![image](https://user-images.githubusercontent.com/63335518/156728031-9ac5e7e4-829d-407a-93da-07b7bb3823bd.png)
![image](https://user-images.githubusercontent.com/63335518/156728071-3d8a34ad-a8d5-4027-9371-a15b21823462.png)
![image](https://user-images.githubusercontent.com/63335518/156728351-fb2c0a82-a75c-4697-867f-631c5f10ce1a.png)


```
scp -P 2244 'root@5.5.5.100:/opt/share/cer.cer' C:\Users\user\Desktop\
```
![image](https://user-images.githubusercontent.com/63335518/156728100-0e3affd8-640e-4c11-ac66-3cf0ad978372.png)

