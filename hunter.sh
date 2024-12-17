#!/bin/bash

    url=$1
    
#    echo $url > var; sed 's/https\?:\/\///g' var >> var1
#    sed '1d' var1 | cut -d '/' -f 1 | tee var
#    url=$(cat var)
 
    
    if [ ! -d "$url" ];then
        mkdir $url
    fi
    if [ ! -d "$url/recon" ];then
        mkdir $url/recon
    fi
    if [ ! -d "$url/recon/gowitness" ];then
    	mkdir $url/recon/gowitness
    fi
    if [ ! -d "$url/recon/scans" ];then
        mkdir $url/recon/scans
    fi
    if [ ! -d "$url/recon/httpx" ];then
        mkdir $url/recon/httpx
    fi
    if [ ! -d "$url/recon/potential_takeovers" ];then
        mkdir $url/recon/potential_takeovers
    fi
    if [ ! -d "$url/recon/wayback" ];then
        mkdir $url/recon/wayback
    fi
    if [ ! -d "$url/recon/wayback/params" ];then
        mkdir $url/recon/wayback/params
    fi
    if [ ! -d "$url/recon/wayback/extensions" ];then
        mkdir $url/recon/wayback/extensions
    fi
    if [ ! -d "$url/recon/whatweb" ];then
        mkdir $url/recon/whatweb
    fi
    if [ ! -f "$url/recon/httpx/alive.txt" ];then
        touch $url/recon/httpx/alive.txt
    fi
    if [ ! -f "$url/recon/final.txt" ];then
        touch $url/recon/final.txt
    fi
    
    echo "[+] Harvesting subdomains with assetfinder..."
    assetfinder $url >> $url/recon/assets.txt
    cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
    rm $url/recon/assets.txt
    
    echo "[+] Harvesting subdomains with subfinder..."
    subfinder -d $url >> $url/recon/sub.txt
    sort -u $url/recon/sub.txt >> $url/recon/final.txt
    rm $url/recon/sub.txt
    
    #echo "[+] Harvesting subdomains with amass..."
    #amass enum -d $url >> $url/recon/f.txt
    #sort -u $url/recon/f.txt >> $url/recon/final.txt
    #rm $url/recon/f.txt
    
    echo "[+] Probing for alive domains..."
    cat $url/recon/final.txt | sort -u | httpx -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' | sort -u >> $url/recon/httpx/httpx.txt
    sort -u $url/recon/httpx/httpx.txt >> $url/recon/httpx/alive.txt
    rm $url/recon/httpx/httpx.txt
    
    echo "[+] Checking for possible subdomain takeover..."
    if [ ! -f "$url/recon/potential_takeovers/takeovers.txt" ];then
        touch $url/recon/potential_takeovers/takeovers.txt
    fi
    subjack -w $url/recon/final.txt -t 100 -timeout 30 -ssl -c ~/home/kratos/go/pkg/mod/github.com/haccer/subjack@v0.0.0-20201112041112-49c51e57deab/fingerprints.json -v 3 -o $url/recon/potential_takeovers/takeovers.txt
    
    echo "[+] Running whatweb on compiled domains..."
    for domain in $(cat ~/$url/recon/httpx/alive.txt);do
        if [ ! -d  "$url/recon/whatweb/$domain" ];then
            mkdir $url/recon/whatweb/$domain
        fi
        if [ ! -f "$url/recon/whatweb/$domain/output.txt" ];then
            touch $url/recon/whatweb/$domain/output.txt
        fi
        if [ ! -f "$url/recon/whaweb/$domain/plugins.txt" ];then
            touch $url/recon/whatweb/$domain/plugins.txt
        fi
        echo "[*] Pulling plugins data on $domain $(date +'%Y-%m-%d %T') "
        whatweb --info-plugins -t 50 -v $domain >> $url/recon/whatweb/$domain/plugins.txt; sleep 3
        echo "[*] Running whatweb on $domain $(date +'%Y-%m-%d %T')"
        whatweb -t 50 -v $domain >> $url/recon/whatweb/$domain/output.txt; sleep 3
    done
    
    echo "[+] Scraping wayback data..."
    cat $url/recon/final.txt | waybackurls >> $url/recon/wayback/wayback_output1.txt
    sort -u $url/recon/wayback/wayback_output1.txt >> $url/recon/wayback/wayback_output.txt
    rm $url/recon/wayback/wayback_output1.txt
    
    echo "[+] Pulling and compiling all possible params found in wayback data..."
    cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
    for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done
    
    echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
    for line in $(cat $url/recon/wayback/wayback_output.txt);do
        ext="${line##*.}"
        if [[ "$ext" == "js" ]]; then
            echo $line | sort -u | tee -a  $url/recon/wayback/extensions/js1.txt
            sort -u $url/recon/wayback/extensions/js1.txt >> $url/recon/wayback/extensions/js.txt
        fi
        if [[ "$ext" == "html" ]];then
            echo $line | sort -u | tee -a $url/recon/wayback/extensions/jsp1.txt
            sort -u $url/recon/wayback/extensions/jsp1.txt >> $url/recon/wayback/extensions/jsp.txt
        fi
        if [[ "$ext" == "json" ]];then
            echo $line | sort -u | tee -a $url/recon/wayback/extensions/json1.txt
            sort -u $url/recon/wayback/extensions/json1.txt >> $url/recon/wayback/extensions/json.txt
        fi
        if [[ "$ext" == "php" ]];then
            echo $line | sort -u | tee -a $url/recon/wayback/extensions/php1.txt
            sort -u $url/recon/wayback/extensions/php1.txt >> $url/recon/wayback/extensions/php.txt
        fi
        if [[ "$ext" == "aspx" ]];then
            echo $line | sort -u | tee -a $url/recon/wayback/extensions/aspx1.txt
            sort -u $url/recon/wayback/extensions/aspx1.txt >> $url/recon/wayback/extensions/aspx.txt
        fi
    done
    
    rm $url/recon/wayback/extensions/js1.txt
    rm $url/recon/wayback/extensions/jsp1.txt
    rm $url/recon/wayback/extensions/json1.txt
    rm $url/recon/wayback/extensions/php1.txt
    rm $url/recon/wayback/extensions/aspx1.txt
    
    echo "[+] Scanning for open ports..."
    nmap -iL $url/recon/httpx/alive.txt -T4 -oA $url/recon/scans/scanned.txt
    
    echo "[+] Running gowitness against all compiled domains..."
    gowitness scan file -s $url/recon/httpx/alive.txt -d $url/recon/gowitness
