#! /bin/bash
cd /home/ubuntu/
touch export.sh
sudo chmod 775 export.sh
echo export access_key=${a_key} >> export.sh
echo export secret_key=${s_key} >> export.sh
echo export END_POINT=${endpoint} >> export.sh
echo export Bucket_name=${bucket_name} >> export.sh
echo export database_name=${database_name} >> export.sh
echo export username=${username} >> export.sh
echo export password=${password} >> export.sh
