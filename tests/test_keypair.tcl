#! /usr/bin/env tclsh

#set pkcs11_module "/usr/local/lib/libcackey.so"
set pkcs11_module "/usr/local/lib64/libls11sw2016.so"
#set pkcs11_module "/usr/local/lib64/librtpkcs11ecp_2.0.so"

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
#Генерация ключей
set aa [list "pkcs11_handle" $handle "pkcs11_slotid" $token_slotid]
puts "Выберите тип генерируемой ключевой пары: 1 - gostr34.10-2012-512 иначе gostr34.10-2012-256"
gets stdin yes

puts "Enter PIN user for you token \"$token_slotlabel\":"
#set password "01234567"
gets stdin password
pki::pkcs11::login $handle $token_slotid $password

if {$yes == "1"} {
    array set genkey [::pki::pkcs11::keypair g12_512 A $aa ]
    puts "Ключевая пара gostr34.10-2012-512 создана"
} else {
    array set genkey [::pki::pkcs11::keypair g12_256 A $aa ]
    puts "Ключевая пара gostr34.10-2012-256 создана"
}
parray genkey
#####################
puts "PUBKEYINFO=$genkey(pubkeyinfo)"

lappend aa "pkcs11_id"
lappend aa $genkey(pkcs11_id)
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

