#! /usr/bin/env tclsh

#set pkcs11_module "/usr/local/lib/libcackey.so"
#set pkcs11_module "/usr/local/lib64/libls11sw2016.so"
set pkcs11_module "/usr/local/lib64/librtpkcs11ecp_2.0.so"

load ./tclpkcs11.so Tclpkcs11

set handle [pki::pkcs11::loadmodule $pkcs11_module]
puts "Handle: $handle"

set slots [pki::pkcs11::listslots $handle]
puts "Slots: $slots"
foreach slotinfo $slots {
	set slotid [lindex $slotinfo 0]
	set slotlabel [lindex $slotinfo 1]
	set slotflags [lindex $slotinfo 2]

	if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
		set token_slotlabel $slotlabel
		set token_slotid $slotid
		break
	}
}

puts "$token_slotlabel: $slotid"
puts "$token_slotlabel: $token_slotid"
#set password "01234567"
puts "Enter type obj (all|cert|pubkey|privkey|data):"
gets stdin typeobj
#set typeobj privkey

if {$typeobj == "privkey" || $typeobj == "all"} {
    puts "Enter PIN user for you token \"$token_slotlabel\":"
    gets stdin password
    pki::pkcs11::login $handle $token_slotid $password
}
#set listobj [::pki::pkcs11::listobjects $handle $token_slotid data]
set listobj [::pki::pkcs11::listobjects $handle $token_slotid $typeobj]
puts "СПИСОК:"
foreach obj $listobj {
    puts "$obj"
}
if {$typeobj == "privkey" || $typeobj == "all"} {
    pki::pkcs11::logout $handle $token_slotid
}
set listobj [::pki::pkcs11::listobjects $handle $token_slotid pubkey value]
puts "СПИСОК VALUE:"
foreach obj $listobj {
    puts "$obj"
}
pki::pkcs11::unloadmodule $handle

