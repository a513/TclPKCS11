#!/usr/bin/tclsh

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

lappend auto_path .
#set auto_path [linsert $auto_path 1 .]
package require pki::pkcs11
set lib "/usr/local/lib64/libls11sw2016.so"
#set lib "/usr/local/lib64/librtpkcs11ecp_2.0.so"
set handle [pki::pkcs11::loadmodule $lib]
#Не забудьте вставить токен
#Получаем список слотов с метками подключенных токенов
set labslot [::slots_with_token $handle]
if {[llength $labslot] == 0} {
    puts "Вы не подключили ни одного токена"
    exit
}
puts $labslot
set slotid 0
set certsder [pki::pkcs11::listcertsder $handle $slotid]
#Берем для разбора первый сертификат
array set derc [lindex $certsder 0]
parray derc
array set certp [pki::x509::parse_cert [binary format H* $derc(cert_der)]]
parray certp
