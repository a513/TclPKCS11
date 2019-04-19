#! /usr/bin/env tclsh

#set pkcs11_module "/usr/local/lib/libcackey.so"
set pkcs11_module "/usr/local/lib64/libls11sw2016.so"
#set pkcs11_module "/usr/local/lib64/librtpkcs11ecp_2.0.so"

load ./tclpkcs11.so Tclpkcs11

#################
proc ::asn1pubkeyinfo {pubkey_algo_asn1 gostR3410params gostR3411params pubkey_hex} {
    set typekey [binary format H* $pubkey_algo_asn1]
    set signparam [binary format H* $gostR3410params]
    set hashparam [binary format H* $gostR3411params]
    if {[string length $pubkey_hex] > 128} {
	set pubkey [binary format H* "048180$pubkey_hex"]
    } else {
	set pubkey [binary format H* "0440$pubkey_hex"]
    }
    binary scan $pubkey B* pubkey_bitstring
    set pubkeyinfo [::asn::asnSequence \
	$typekey \
	    [::asn::asnSequence \
			$signparam \
			$hashparam \
	    ] \
    ] 
    
    set keyinfo [::asn::asnBitString "$pubkey_bitstring"]
    
    binary scan $pubkeyinfo$keyinfo H* pubkeyinfo_hex
#    puts "pubkeyinfo_hex=$pubkeyinfo_hex"
    return $pubkeyinfo_hex
}
###################

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
#Генерация ключей
set aa [list "pkcs11_handle" $handle "pkcs11_slotid" $token_slotid]
puts "Выберите тип генерируемой ключевой пары: 1 - gostr34.10-2012-512 иначе gostr34.10-2012-256"
gets stdin yes

puts "Enter PIN user for you token \"$token_slotlabel\":"
#set password "01234567"
gets stdin password
pki::pkcs11::login $handle $token_slotid $password

if {$yes == "1"} {
    set tbs_csr "Подпись по gostr3410-12-512"
    array set genkey [::pki::pkcs11::keypair g12_512 A $aa ]
    puts "Ключевая пара gostr34.10-2012-512 создана"
    set digest_hex    [pki::pkcs11::digest "stribog512" $tbs_csr  $aa]
    set ckmpair CKM_GOSTR3410_512
} else {
    set tbs_csr "Подпись по gostr3410-12-256"
    array set genkey [::pki::pkcs11::keypair g12_256 A $aa ]
    puts "Ключевая пара gostr34.10-2012-256 создана"
    set digest_hex    [pki::pkcs11::digest "stribog256" $tbs_csr  $aa]
    set ckmpair CKM_GOSTR3410
}
lappend aa "pkcs11_id"
lappend aa $genkey(pkcs11_id)
set sign1_hex  [pki::pkcs11::sign $ckmpair $digest_hex  $aa]
parray genkey
#set pkhex [::asn1pubkeyinfo $genkey(pubkey_algo_asn1) $genkey(gostR3410params) $genkey(gostR3411params) $genkey(pubkey)]
puts "PUBKEYINFO=$genkey(pubkeyinfo)"
set vpk [list "pkcs11_handle" $handle "pkcs11_slotid" $token_slotid]
lappend vpk "pubkeyinfo"
#lappend lpk $pubinfo
lappend vpk $genkey(pubkeyinfo)

if {[catch {set verify [pki::pkcs11::verify $digest_hex $sign1_hex $vpk]} res] } {
    puts $res
    exit
}
if {$verify != 1} {
    puts "BAD SIGNATURE=$verify"
} else {
    puts "SIGNATURE OK=$verify"
}

puts "Сменить метку ключевой пары? Введите да или нет:"
gets stdin yes
if {$yes == "да"} {
    puts "Введите новую метку для ключевой пары"
    gets stdin labkey
#    dict set aa pkcs11_slotid $genkey(pkcs11_id)
    lappend aa "pkcs11_label"
    lappend aa $labkey
    puts "AA_RENAME=$aa"
    pki::pkcs11::rename key $aa
    puts "Установлена метка $labkey"
}
puts "Удалить созданную ключевую пару? Введите да или нет:"
gets stdin yes
if {$yes == "да"} {
    pki::pkcs11::delete key $aa
    puts "Ключевая пара удалена"
}

pki::pkcs11::logout $handle $token_slotid

pki::pkcs11::unloadmodule $handle

exit

