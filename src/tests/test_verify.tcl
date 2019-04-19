#! /usr/bin/env tclsh
package require pki
lappend auto_path .
package require pki::pkcs11
#Задайте путь к вашей библиотеке PKCS#11
#set pkcs11_module "/usr/local/lib/libcackey.so"
#set pkcs11_module "/usr/local/lib64/librtpkcs11ecp_2.0.so"
set pkcs11_module "/usr/local/lib64/libls11sw2016.so"
puts "Connect the Token and press Enter"
gets stdin yes

set handle [pki::pkcs11::loadmodule $pkcs11_module]
set slots [pki::pkcs11::listslots $handle]
foreach slotinfo $slots {
	set slotid [lindex $slotinfo 0]
	set slotlabel [lindex $slotinfo 1]
	set slotflags [lindex $slotinfo 2]

	if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
		set token_slotlabel $slotlabel
		set token_slotid $slotid
#Найден слот с токеном
		break
	}
}

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

proc usage {use error} {
    puts "Copyright(C) Orlov Vladimir (http://soft.lissi.ru) 2019"
    if {$use == 1} {
	puts $error
	puts "Usage:\nverify_cert_with_pkcs11 <file with certificate> \[<file with CA certificate>\]\n"
    }
}

set countcert [llength $argv]
if { $countcert < 1 ||  $countcert > 2 } {
    usage 1 "Bad usage!"
    exit
}
set file [lindex $argv 0]
if {![file exists $file]} {
    usage 1 "File $file not exist"
    exit
}
#Проверяемый сертификат cert_user
puts "Loading user certificate: $file"
set fd [open $file]
chan configure $fd -translation binary
set cert_user [read $fd]
close $fd
if {$cert_user == "" } {
    usage 1 "Bad file with certificate: $file"
    exit
}
set cert_user [cert_to_der $cert_user]
if {$cert_user == ""} {
    puts "User certificate bad"
    exit
}

catch {array set cert_parse [::pki::x509::parse_cert $cert_user]}
#array set cert_parse [::pki::x509::parse_cert $cert_256]
#array set cert_parse [::pki::x509::parse_cert $cert_512]
#array set cert_parse [::pki::x509::parse_cert $test12_512]
if {![info exists cert_parse]} {
    puts "User certificate bad"
    exit
}
#parray cert_parse
if {$countcert == 1} {
    if {$cert_parse(issuer) != $cert_parse(subject)} {
	puts "Bad usage: not self signed certificate"
    } else {
	set cert_CA $cert_user
    }
} else {
    set fileca [lindex $argv 1]
    if {![file exists $fileca]} {
	usage 1 "File $fileca not exist"
	exit
    }
    #Сертификат издателя cert_CA
    puts "Loading CA certificate: $fileca"
    set fd [open $fileca]
    chan configure $fd -translation binary
    set cert_CA [read $fd]
    close $fd
    if {$cert_CA == "" } {
	usage 1 "Bad file with certificate user=$fileca"
	exit
    }
    set cert_CA [cert_to_der $cert_CA]
    if {$cert_CA == ""} {
	puts "CA certificate bad"
	exit
    }
}

foreach slotinfo $slots {
	set slotid [lindex $slotinfo 0]
	set slotlabel [lindex $slotinfo 1]
	set slotflags [lindex $slotinfo 2]

	if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
		set token_slotlabel $slotlabel
		set token_slotid $slotid
	}
}

#Ключ от корневого сертификата
#array set cert_parse_CA [::pki::x509::parse_cert $cert_CA]
catch {array set cert_parse_CA [::pki::x509::parse_cert $cert_CA]}
#array set cert_parse_CA [::pki::x509::parse_cert $cert_CA_256]
#array set cert_parse_CA [::pki::x509::parse_cert $CA_12_512]
if {![info exists cert_parse_CA]} {
    puts "CA certificate bad"
    exit
}


###############################
set aa [dict create pkcs11_handle $handle pkcs11_slotid $token_slotid]
set tbs_cert [binary format H* $cert_parse(cert)]
#puts "SIGN_ALGO1=$cert_parse(signature_algo)"
catch {set signature_algo_number [::pki::_oid_name_to_number $cert_parse(signature_algo)]}
if {![info exists signature_algo_number]} {
    set signature_algo_number $cert_parse(signature_algo)
}
#puts "SIGN_ALGO=$signature_algo_number"
switch -- $signature_algo_number {
    "1.2.643.2.2.3" - "1 2 643 2 2 3" { 
#    "GOST R 34.10-2001 with GOST R 34.11-94"
	set digest_algo "gostr3411"
    }
    "1.2.643.7.1.1.3.2" - "1 2 643 7 1 1 3 2" {
#     "GOST R 34.10-2012-256 with GOSTR 34.11-2012-256"
	set digest_algo "stribog256"
    }
    "1.2.643.7.1.1.3.3" - "1 2 643 7 1 1 3 3" { 
#    "GOST R 34.10-2012-512 with GOSTR 34.11-2012-512"
	set digest_algo "stribog512"
    }
    default {
	puts "Неизвестная алгоритм подписи:$signature_algo_number"
	exit
    }
}

#Посчитать хэш от tbs-сертификата!!!!
set digest_hex    [pki::pkcs11::digest $digest_algo $tbs_cert  $aa]

puts "digest_hex=$digest_hex"
puts [string length $digest_hex]
#Получаем asn-структуру публичного ключа
#Создаем список ключевых элементов

binary scan $cert_CA H* cert_CA_hex
array set infopk [pki::pkcs11::pubkeyinfo $cert_CA_hex  [list pkcs11_handle $handle pkcs11_slotid $token_slotid]] 
parray infopk

set lpk [dict create pkcs11_handle $handle pkcs11_slotid $token_slotid]
#Добавляем pybkeyinfo в список ключевых элементов
lappend lpk "pubkeyinfo"
#lappend lpk $pubinfo
lappend lpk $infopk(pubkeyinfo)

array set lpkar $lpk
parray lpkar
puts "Enter PIN user for you token \"$token_slotlabel\":"
#set password "01234567"
gets stdin password

if { [pki::pkcs11::login $handle $token_slotid $password] == 0 } {
    puts "Bad password"
    exit
}

if {[catch {set verify [pki::pkcs11::verify $digest_hex $cert_parse(signature) $lpk]} res] } {
    puts $res
    exit
}
if {$verify != 1} {
    puts "BAD SIGNATURE=$verify"
} else {
    puts "SIGNATURE OK=$verify"
}
puts "Конец!"
exit
