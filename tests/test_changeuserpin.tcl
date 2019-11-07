#! /usr/bin/env tclsh

#set pkcs11_module "/usr/local/lib/libcackey.so"
set pkcs11_module "/usr/local/lib64/libls11sw2016.so"
#set pkcs11_module "/usr/local/lib64/librtpkcs11ecp_2.0.so"

load ./tclpkcs11.so Tclpkcs11

set handle [pki::pkcs11::loadmodule $pkcs11_module]
puts "Handle: $handle"
if {1} {
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
}
puts "$token_slotlabel: $slotid"
puts "token_slotid = \"$token_slotid\""
puts "Enter user PIN  for you token:"
gets stdin userpin
puts "Enter new user PIN  for you token:"
gets stdin newpin
set ret [pki::pkcs11::setpin $handle $token_slotid user $userpin $newpin]
if {$ret == 0 } {
    puts "inituserpin: Bad User-PIN"
    exit
}
exit

