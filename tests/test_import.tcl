#! /usr/bin/env tclsh

#Из PEM в DET
proc ::cert_to_der {data} {
    if {[string first "-----BEGIN CERTIFICATE-----" $data] != -1} {
	set data [string map {"\r\n" "\n"} $data]
    }
    array set parsed_cert [::pki::_parse_pem $data "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----"]
    if {[string range $parsed_cert(data) 0 0 ] == "0" } {
#Очень похоже на DER-кодировка "0" == 0x30 
	set asnblock $parsed_cert(data)
    } else {
	set asnblock ""
    }
    return $asnblock
}

#set pkcs11_module "/usr/local/lib/libcackey.so"
#set pkcs11_module "/usr/local/lib64/libls11sw2016.so"
set pkcs11_module "/usr/local/lib64/librtpkcs11ecp_2.0.so"

puts "START TEST"
load ./tclpkcs11.so Tclpkcs11
puts "TEST LOAD"

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

puts "$token_slotlabel: $slotlabel"
puts "$token_slotid: $token_slotid"

#Читаем сертификат для импорта
if {[llength $argv] == 2} {
    set file [lindex $argv 0]
    set labCert [lindex $argv 1]
} else {
	puts "Not certificate"
	puts "test import <cert> <label>"
	exit
}

set fd [open $file]
chan configure $fd -translation binary
set data [read $fd]
close $fd
set asndata [::cert_to_der $data]
if {$asndata == "" } {
	puts "Bad certificate=$file"
	exit
}
binary scan $asndata H* cert_der_hex

set listcert {}

set uu [dict create pkcs11_handle $handle]
dict set uu pkcs11_slotid $token_slotid
lappend uu "pkcs11_label"
lappend uu $labCert
puts "LISTforP11=$uu"
set pkcs11id [pki::pkcs11::importcert $cert_der_hex $uu]
puts "PKCS11ID=$pkcs11id"
unset uu
set uu [dict create pkcs11_handle $handle]
dict set uu pkcs11_slotid $token_slotid
lappend uu "pkcs11_id"
lappend uu $pkcs11id
puts "Сменить метку сертификата и ключей? Введите да или нет:"
gets stdin yes
if {$yes == "да"} {
    puts "Введите новую метку для сертификата"
    gets stdin labCert
#dict set uu pkcs11_slotid $token_slotid
lappend uu "pkcs11_label"
lappend uu $labCert
    pki::pkcs11::rename all $uu
    puts "Установлена метка $labCert"
}
puts "Удалить импортированный сертификат? Введите да или нет:"
gets stdin yes
if {$yes == "да"} {
    pki::pkcs11::delete cert $uu
    puts "Сертификат удален"
}
if {0} {
	    set uu [dict create pkcs11_handle $::handle]
	    dict set uu pkcs11_slotid $::slotid_tek
	    dict set uu pkcs11_label $labcert
	    dict set uu pkcs11_id $infopk(pkcs11_id)
	    dict set uu priv_value $private_key_str_hex
	    dict set uu priv_export "true"
	    dict set uu pub_value $public_key_str_hex
	    dict set uu gosthash $asnhash_hex
	    dict set uu gostsign $asnsign_hex
	    if {[catch {set impkey [pki::pkcs11::importkey $uu ]} res] } {
		set impkey 0
	    }
	    if {$impkey} {
		puts "Ключевая пара успешно импортирована:\nCKA_LABEL: $labcert\nCKA_ID: $infopk(pkcs11_id)"
	    } else {
		puts "Cannot import pairkey: $res"
	    }
}
exit

