#!/bin/bash
key=.key
clear

banner (){
    clear
    echo "All in One Tools (Golden)"
    sleep 1
    echo "User :" $(sed -n '1p' .key)
}
menu (){
    banner
    echo """
    SILAHKAN PILIH MENU !!
    1) Edit Data Snif
    2) Rekap Data (Experimental, tidak dianjurkan)
    3) Panduan (Penting)
    """
}

manage (){
    echo
    echo """
    [1] Hapus File Bekas
    [2] Cadangkan
    """
    echo -n "Pilihanmu : "
    read bckup
    if [ "$bckup" -eq 1 ]; then
        rm -rf /storage/emulated/0/HttpCanary/Download/*
    elif [ "$bckup" -eq 2 ]; then
        zip -rm Backup_$result /storage/emulated/0/HttpCanary/Download/*
    else
        read -p "Masukkan pilihan dengan benar!! [Enter]"
        manage
    fi
}
snif (){
    clear
    banner
    xData=.xdata
    if test -f "$xData"; then
        rm .xdata
    else
        touch .xdata
    fi
    echo
    echo "Beri Nama File !"
    echo -n "Nama File : "
    read result
    for i in $(ls */request.hcy */*/request.hcy */*/*/request.hcy */*/*/*/request.hcy)
    do
        sleep 0.13
        if test -f "$i"; then
            sed -n '1p' $i >>.xdata && echo "Sukses ->" $i || echo "Gagal"
        else
            echo "Something went wrong, please contact author"
        fi
    done
    
    echo '<?php' >$result.php
	echo '$data = [' >>$result.php
	sort -u .xdata | tr '/' ' ' | sed -e 's/POST  rest v1 stat collect?mobile=/"/' | sed -e 's/ HTTP 1.1/",/' >>$result.php
	echo '];' >>$result.php
	manage
    sleep 2
    echo "Selesai✓"
    read -p "Tekan [enter] untuk melanjutkan"
}
load (){
	a=1
	while [ $a -lt 101 ]
	do
		sleep 0.34
	    echo -ne "Tunggu Sebentar ($a)\r"
	    ((a++))
	    ((a++))
	    ((a++))
	done
}
rekap (){
    clear
    banner
    echo "Tentukan Nama File!"
    echo -n "Nama File : "
    read rekap
    for i in $(ls */userid.php */*/userid.php)
    do
        sleep 0.3
        echo "Data ditemukan! ->" $i
        cat $i >>$rekap
    done
    load
    echo
    echo "Selesai ✓"
    
}
panduan (){
    clear
    banner
    echo """
    
    *Proses sniffing data dilakukan secara berurutan
    
    [TAHAP PERTAMA]
    1. Clone game
    2. Hidupkan HttpCanary 
    3. Buka game dan tunggu hingga loading selesai & masuk ke menu permainan
    4. Keluar game dan hapus dari recent apps
    5. Buka game clone yang lainnya
    6. Ulangi langkah 3-5 hingga game terakhir
    
    [TAHAP KEDUA]
    1. Kembali ke HttpCanary
    2. Matikan Capture-nya
    3. Tekan titik tiga di pojok kanan atas
    4. Tekan (Filter)
    5. Tekan (Http)
    6. Atur seperti di bawah ini

    Http Method : POST
    Status Code : 200
    Url Keyword : stat.
    
    Jika sudah, kembali ke menu awal
    
    7. Lalu tekan titik 3 lagi
    8. Tekan (Sellect All)
    9. Kemudian tekan & tahan salah satu data yang ada di daftar capture
    10. Tekan (Save) & beri nama folder (bebas)  *apabila dimintai ijin penyimpanan, ijinkan saja
    
    Kembali ke script edit ini dan jalankan menu pertama [Edit Data Snif]
    *Hubungi admin jika merasa kebingungan
    """
    sleep 5
    read -p "Tekan Enter [Enter] Untuk Melanjutkan"
}

if test -f "$key"; then
echo "You're Verified User "
read -p "Tekan Enter [Enter] Untuk Melanjutkan"
menu
else
echo "You're Not User!! Sign Up First"
read -p "Tekan Enter [Enter] Untuk Melanjutkan"
signup
fi

echo -n "Masukan pilihanmu : "
read pilih
if [ "$pilih" -eq 1 ]; then
	snif
elif [ "$pilih" -eq 2 ]; then
	rekap
elif [ "$pilih" -eq 3 ]; then
	panduan
else
	echo "PILIH !! "
fi







