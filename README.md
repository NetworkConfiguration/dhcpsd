# dhcpsd

dhcpsd is a very simple
[DHCP](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)
server.
It's designed to just to the basics of DHCP and offload the more complex
things such as configuration to plugins.

The rationale is this: A traditional DHCP server configuration is overly
complex and daunting to an adminsitrator of any skill level.
So how can we make it easier?
The answer to make the configuration driven by plugins and not a single
complex entity.

Why plugins?
Well, I don't know how you want to store your configuration or leases.
Flat file? Database, if so which flavour?
Maybe you want to inject your configuration from something else!
Heck, I just don't know.

## Auto Configuration
If you don't specify any plugins then you get the `auto` plugin.
This plugin will scan all interfaces and if it finds a
[RFC1918 private address](https://datatracker.ietf.org/doc/html/rfc1918)
ending with a `.1` it will create a pool starting from `.10` to `.254`
for the range of the subnet.
It will also offer itself as both a Router and DNS server as well as
lease time of upto 1 hour (clients can request lower).

## Lease File
If you don't specify any plugins them you also get the `leasefile` plugin.
This plugin will save the current leases in a tab seperated format
to `/var/db/dhcpsd/dhcp.leases`.
Every 30 seconds this plugin will *tick* and if a lease was added, changed
or removed then this file will be re-written.
It's also saved when dhcpsd terminates.

## Static IP address mapping
Static IP addess mapping is managed by either the `ethers` plugin
to map a hardware address to an ip address
and/or the `addrinfo` plugins which maps a hostname to an ip address.
Respectively they access the
[ethers(5)](https://man.netbsd.org/ethers.5)
or
[getaddrinfo(3)](https://man.netbsd.org/getaddrinfo.3)
databases.

You can even use both plugins - first success wins.

## Lua
The lua plugin loads `/etc/dhcpsd/dhcp.lua` so you can programatically
define the address pools, static address mappings, customise the
DHCP response based on the request and trigger actions based on the
state of a comitted or expired lease.

Here is an example of how to use it.

```lua
-- Hostnames should be fully qualified.
-- If a domain isn't specified in the hostname then this will be appended.
local domain = 'internal'

-- Lookup table to match hostname to IP address.
local hostnames = {
	['netbsd'] = '10.73.1.70',
}

-- Lookup table to match ethernet to hostnames.
local ethers = {
	['52:54:00:73:00:00'] = 'netbsd',
}

-- Lookup table to match hardware type.
local htypes = {
	[1] = ethers,
}

-- Lookup table for DHCP options, saves us using magic numbers below.
local dhcp_opts = {
	['SUBNETMASK'] = 1,
	['ROUTER'] = 3,
	['DNSSERVER'] = 6,
	['HOSTNAME'] = 12,
	['DNSDOMAIN'] = 15,
	['PARAMETERREQUESTLIST'] = 55,
	['FQDN'] = 81,
}

-- Checks if the client requested the DHCP option or not.
local function has_parameter_request(opt)
	local oro = dhcp.get_option(dhcp_opts['PARAMETERREQUESTLIST'])
	if oro == nil then
		return false
	end
	if (string.find(oro, string.char(opt))) == nil then
		return false
	end
	return true
end

-- dhcpsd will call this function to make IP address pools for the interface.
-- You can return a single table with address, netmask, from and to
-- or a table of the above table (ie an array).
-- Each address MUST exist on the interface.
function configure_pools(if_name)
	if if_name == 'bridge0' then
		return {
			address = '10.73.1.1',
			netmask = '255.255.255.0',
			from = '10.73.1.100',
			to = '10.73.1.200',
		}
	end
end

local function add_domain(hostname)
	if hostname == nil or domain == nil or
		string.find(hostname, '%.') ~= nil
	then
		return hostname
	end
	return hostname .. '.' .. domain
end

local function ends_with_domain(hostname)
	if hostname == nil or domain == nil then
		return false
	end
	local d = '.' .. domain
	if string.sub(hostname, -string.len(d)) ~= d then
		return false
	end
	return true
end

local function trim_domain(hostname)
	if hostname ~= nil and ends_with_domain(hostname) then
		return string.sub(hostname, 1, string.len(domain) + 1)
	end
	return hostname
end

local function _lookup_hostname(htype, chaddr)
	local chaddrs = htypes[htype]
	if chaddrs ~= nil then
		return chaddrs[chaddr]
	end
end

-- dhcpsd will call this function to match a host to a hostname.
function lookup_hostname(htype, chaddr)
	local hname = _lookup_hostname(htype, chaddr)
	return add_domain(hname)
end

-- dhcpsd will call this function to match a host to an IP address.
function lookup_addr(hostname, htype, chaddr)
	local hname = _lookup_hostname(htype, chaddr)
	if hname ~= nil then
		hostname = hname
	end

	local addr = hostnames[hostname]
	if addr ~= nil then
		return addr
	end

	-- If the client has a fqdn hostname and we are being lazy by
	-- setting the domain at the top we need to trim it and look it up
	if hname == nil and hostname ~= nil and ends_with_domain(hostname) then
		hname = string.sub(hostname, 1, string.len(domain) + 2)
		return hostnames[hostname]
	end
end

-- dhcpsd will call this function to add options to a DHCP reply.
-- Return non zero to stop other plugins applying options.
function add_dhcp_options(hostname, htype, chaddr)
	if has_parameter_request(dhcp_opts['SUBNETMASK']) then
		dhcp.add_ip(dhcp_opts['SUBNETMASK'], '255.255.255.0')
	end
	if has_parameter_request(dhcp_opts['ROUTER']) then
		dhcp.add_ip(dhcp_opts['ROUTER'], '10.73.1.1')
	end
	if has_parameter_request(dhcp_opts['DNSSERVER']) then
		dhcp.add_ip(dhcp_opts['DNSSERVER'], '10.73.1.1, 10.73.1.2')
	end

	hostname = trim_domain(hostname)
	if dhcp.get_option(dhcp_opts['HOSTNAME']) == 'netbsd' then
		dhcp.set_bootp_file('/boot-netbsd.img')
		dhcp.set_bootp_sname('tftp.local')
	elseif hostname == 'freebsd' then
		dhcp.set_bootp_file('/boot-freebsd.img')
		dhcp.set_bootp_sname('tftp.local')
		-- This is a buggy host so force this option in
		dhcp.add_string(dhcp_opts['DNSDOMAIN'], 'barfoo')
	else
		if has_parameter_request(dhcp_opts['DNSDOMAIN']) then
			dhcp.add_string(dhcp_opts['DNSDOMAIN'], 'foobar')
		end
	end
	return 1
end

local function arpa_ip(ip)
	local arpa = "in-addr.arpa."

	for a in string.gmatch(ip, "([^%.]+)") do
		arpa = a .. "." .. arpa
	end

	return arpa
end

--[[
-- example helper functions to update a DNS server using nsupdate(8).
-- You will need to install and configure nsupdate yourself,
-- or update your DNS server using some other means.
local function delete_dns(hostname, ip, flags)
	local arpa = arpa_ip(ip)

	if string.find(flags, "p") then
		os.execute("printf 'update delete " .. arpa .. " PTR\n"
			.. "send\n'"
			.. " | nsupdate")
	end

	if string.find(flags, "a") then
		os.execute("printf 'update delete " .. hostname .. ". A\n"
			.. "send\n'"
			.. " | nsupdate")
	end
end

local function update_dns(hostname, ip, flags, expires)
	-- We should checks the flags for more options:
	-- N means the client wants us to update the A record.
	-- P means the client wants us to update the PTR record.
	-- n means we have previously updated the A record.
	-- p means we have previously updated the PTR record.
	-- If the FQDN option is present and we don't have
	-- the P flag then then the client does NOT want us to
	-- update DNS at all.
	-- n and p can be returned to indicate what we have done
	local rflags = ""

	-- client did NOT tell us to NOT update DNS
	if string.find(flags, "P") ~= nil
		or dhcp.get_option(dhcp_opts['FQDN']) == nil
	then
		local ttl = string.format("%.0f", os.difftime(expires, os.time()))
		local arpa = arpa_ip(ip)
		local err = os.execute("printf 'update delete " .. arpa .. " PTR\n"
			.. "update add " .. arpa .. " " .. ttl .. " PTR " .. hostname .. ".\n"
			.. "send\n'"
			.. " | nsupdate")
		if err == true then
			rflags = rflags .. "p"
			if string.find(flags, "F") == nil or string.find(flags, "N") ~= nil then
				err = os.execute("printf 'update delete " .. hostname .. ". A\n"
					.. "update add " .. hostname .. ". " .. ttl .. " A " .. ip .. "\n"
					.. "send\n'"
					.. " | nsupdate")
				if err == true then
					rflags = rflags .. "n"
				end
			elseif string.find(flags, "n") then
				-- Unsure if this is the right thing to do as the
				-- client wants to update the PTR but not the A.
				delete_dns(hostname, ip, "n")
			end
		end
	end

	return rflags
end
--]]

---[[
-- dhcpsd will call this function lease time a lease is committed in some way.
-- dhcp.get_option can be called here to interogate the DHCP request from the
-- client, but you cannot set any options.
-- For example you could use this function to maintain entries in a DNS server.
function commit_lease(hostname, htype, chaddr, clientid, ip, flags, leased, expires)
	-- NOTE: dhcpsd MUST be supplied the debug flag to keep stdout open
	local rflags = ""
	local type = "UNKNOWN"
	if string.find(flags, "D") ~= nil or string.find(flags, "d") ~= nil then
		type = "DECLINED"
	elseif string.find(flags, "O") ~= nil then
		type = "OFFERED"
	elseif string.find(flags, "L") ~= nil then
		type = "LEASED"
	elseif string.find(flags, "I") ~= nil then
		type = "INFORMED"
	end

	io.write(string.format("%s: hostname:%s htype:%d chaddr:%s\n" ..
		"clientid:%s ip:%s flags:%s\n" ..
		"leased:%d (%s) expires:%d (%s)\n",
		type, hostname, htype, chaddr, clientid, ip, flags,
		leased, os.date("%c", leased), expires, os.date("%c", expires)))

	-- We could update DNS for a committed LEASE with an Address
	if type == "LEASED" and string.find(flags, "A") ~= nil
		and hostname ~= nil and hostname ~= ''
		and update_dns ~= nil
	then
		rflags = update_dns(hostname, ip, flags, expires)
	end

	return 0, rflags
end
--]]

---[[
-- dhcpcd will call this function when a lease has expired.
-- No dhcp functions can be called here.
-- You could use this function to maintain entries in a DNS server.
function expire_lease(hostname, clientid, ip, flags)
	-- NOTE: dhcpsd MUST be supplied the debug flag to keep stdout open
	io.write(string.format("EXPIRE: hostname:%s clientid: %s ip:%s flags:%s\n",
	hostname, clientid, ip, flags))

	if delete_dns ~= nil then
		delete_dns(hostname, ip, flags)
	end
	return 0
end
--]]
```

## ICMP
During DISCOVER, each address which hasn't been offered to the client before OR
has has passed the expired, declined and released address timers, dhcpsd will
send an ICMP ECHO to the address.

If an ICMP ECHOREPLY is received from the address with the same ID as the ECHO
within 3 seconds then the address is marked as DECLINED for 30 seconds and
dhcpsd will try another address with the same rules until we find a free
address to make an OFFER with.

Until this process completes, any futher DISCOVER messages from the client are
discarded.

It is NOT recommended to use this plugin if your DHCP clients use Duplicate
Address Discovery as recommended in RFC 2131 as they can do a better job
of detecting an in-use address and sending a DECLINE message.

## Anything else?
dhcpsd is secure from the first version.
It supports
[capsicum(4)](https://man.freebsd.org/cgi/man.cgi?capsicum(4)) from FreeBSD,
[pledge(2)](https://man.openbsd.org/pledge.2) from OpenBSD,
[seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html) for Linux
and a POSIX restricted chroot (no forks, no new files) for everything else
apart from Illumos.

dhcpsd is fast by default:
* written in C
* uses the [Verstable](https://github.com/JacksonAllan/Verstable) hashmap
* uses the [NetBSD Red-Black Tree](https://man.netbsd.org/rbtree.3)
* leases are held in two hashmaps, one by address and one by clientid
* leases are also held in a tree ordered by expiry time
* driven by an event loop
  Can handle other requests while handling an icmp echo for example.

## TODO

* DHCPv6
* RA?
