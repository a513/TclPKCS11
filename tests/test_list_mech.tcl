#!/usr/bin/tclsh

lappend auto_path pkcs11
package require pki::pkcs11
#Список токенов со слотами
proc ::slots_with_token {handle} {
    set slots [pki::pkcs11::listslots $handle]
#    puts "Slots: $slots"

    array set listtok []
    foreach slotinfo $slots {
	set slotid [lindex $slotinfo 0]
	set slotlabel [lindex $slotinfo 1]
	set slotflags [lindex $slotinfo 2]

	if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
	    set listtok($slotid) $slotlabel
	}
    }
#Список найденных токенов в слотах
    parray listtok
    return [array get listtok]
}

#set filelib "/usr/local/lib64/librtpkcs11ecp_2.0.so"
#set filelib "/usr/local/lib64/libls11cloud.so"
set filelib "/usr/local/lib64/libls11sw2016.so"


if {[catch {set handle [::pki::pkcs11::loadmodule  $filelib]} res]} {
    puts "Cannot load library $filelib : $res"
    exit
}
set listslots {}
set listslots [::slots_with_token $handle]
while {[llength $listslots] == 0} {
puts "Insert token"
    after 3000
    set listslots [::slots_with_token $handle]
}


foreach {slotid labeltok} $listslots {
	puts "Number slot: $slotid"
	puts  "Label token: $labeltok"
}

set listmechs [pki::pkcs11::listmechs  $handle  $slotid]
puts "listcerts=$listmechs"
foreach mechfromlist $listmechs {
    puts $mechfromlist
}
