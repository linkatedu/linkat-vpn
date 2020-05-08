if [[ $COMPRESSION_ENABLED == "y" ]]; then
                echo "Choose which compression algorithm you want to use: (they are ordered by efficiency)"
                echo "   1) LZ4-v2"
                echo "   2) LZ4"
                echo "   3) LZ0"
                until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
                        read -rp"Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
                done
                case $COMPRESSION_CHOICE in
                1)
                        COMPRESSION_ALG="lz4-v2"
                        ;;
                2)
                        COMPRESSION_ALG="lz4"
                        ;;
                3)
                        COMPRESSION_ALG="lzo"
                        ;;
                esac
        fi
        echo ""
        echo "Do you want to customize encryption settings?"
        echo "Unless you know what you're doing, you should stick with the default parameters provided by the script."
        echo "Note that whatever you choose, all the choices presented in the script are safe. (Unlike OpenVPN's defaults)"
        echo "See https://github.com/angristan/openvpn-install#security-and-encryption to learn more."
        echo ""
        until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
                read -rp "Customize encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
        done

if [[ $CUSTOMIZE_ENC == "n" ]]; then
                # Use default, sane and fast parameters
                CIPHER="AES-128-GCM"
                CERT_TYPE="1" # ECDSA
                CERT_CURVE="prime256v1"
                CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
                DH_TYPE="1" # ECDH
                DH_CURVE="prime256v1"
                HMAC_ALG="SHA256"
                TLS_SIG="1" # tls-crypt
        else
                echo ""
                echo "Choose which cipher you want to use for the data channel:"
                echo "   1) AES-128-GCM (recommended)"
                echo "   2) AES-192-GCM"
                echo "   3) AES-256-GCM"
                echo "   4) AES-128-CBC"
                echo "   5) AES-192-CBC"
                echo "   6) AES-256-CBC"
                until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
                        read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
                done
                case $CIPHER_CHOICE in
                1)
                        CIPHER="AES-128-GCM"
                        ;;
                2)
                        CIPHER="AES-192-GCM"
                        ;;
                3)
                        CIPHER="AES-256-GCM"

;;
                3)
                        CIPHER="AES-256-GCM"
                        ;;
                4)
                        CIPHER="AES-128-CBC"
                        ;;
                5)
                        CIPHER="AES-192-CBC"
                        ;;
                6)
                        CIPHER="AES-256-CBC"
                        ;;
                esac
                echo ""
                echo "Choose what kind of certificate you want to use:"
                echo "   1) ECDSA (recommended)"
                echo "   2) RSA"
                until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
                        read -rp"Certificate key type [1-2]: " -e -i 1 CERT_TYPE
                done
                case $CERT_TYPE in
                1)
                        echo ""
                        echo "Choose which curve you want to use for the certificate's key:"
                        echo "   1) prime256v1 (recommended)"
                        echo "   2) secp384r1"
                        echo "   3) secp521r1"
                        until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
                                read -rp"Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
                        done
                        case $CERT_CURVE_CHOICE in
                        1)
                                CERT_CURVE="prime256v1"
                                ;;
                        2)
                                CERT_CURVE="secp384r1"
                                ;;
                        3)
                                CERT_CURVE="secp521r1"
                                ;;
                        esac
                        ;;
 2)
                        echo ""
                        echo "Choose which size you want to use for the certificate's RSA key:"
                        echo "   1) 2048 bits (recommended)"
                        echo "   2) 3072 bits"
                        echo "   3) 4096 bits"
                        until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
                                read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
                        done
                        case $RSA_KEY_SIZE_CHOICE in
                        1)
                                RSA_KEY_SIZE="2048"
                                ;;
                        2)
                                RSA_KEY_SIZE="3072"
                                ;;
                        3)
                                RSA_KEY_SIZE="4096"
                                ;;
                        esac
                        ;;
                esac
                echo ""
                echo "Choose which cipher you want to use for the control channel:"
                case $CERT_TYPE in
                1)
                        echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
                        echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
                        until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
                                read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
                        done
                        case $CC_CIPHER_CHOICE in
                        1)
                                CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
                                ;;
                        2)
                                CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
                                ;;
                        esac
                        ;;
                2)
                        echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
                        echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
                        until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
                                read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
                        done
                        case $CC_CIPHER_CHOICE in
                        1)
                                CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
                                ;;
                        2)
                                CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
                                ;;
                        esac
;;
                esac
                echo ""
                echo "Choose what kind of Diffie-Hellman key you want to use:"
                echo "   1) ECDH (recommended)"
                echo "   2) DH"
                until [[ $DH_TYPE =~ [1-2] ]]; do
                        read -rp"DH key type [1-2]: " -e -i 1 DH_TYPE
                done
                case $DH_TYPE in
                1)
                        echo ""
                        echo "Choose which curve you want to use for the ECDH key:"
                        echo "   1) prime256v1 (recommended)"
                        echo "   2) secp384r1"
                        echo "   3) secp521r1"
                        while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
                                read -rp"Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
                        done
                        case $DH_CURVE_CHOICE in
                        1)
                                DH_CURVE="prime256v1"
                                ;;
                        2)
                                DH_CURVE="secp384r1"
                                ;;
                        3)
                                DH_CURVE="secp521r1"
                                ;;
                        esac
                        ;;
                2)
                        echo ""
                        echo "Choose what size of Diffie-Hellman key you want to use:"
                        echo "   1) 2048 bits (recommended)"
                        echo "   2) 3072 bits"
                        echo "   3) 4096 bits"
                        until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
                                read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
                        done
                        case $DH_KEY_SIZE_CHOICE in
                        1)
                                DH_KEY_SIZE="2048"
                                ;;
                        2)
                                DH_KEY_SIZE="3072"
                                ;;
                        3)
                                DH_KEY_SIZE="4096"
                                ;;
                        esac
 ;;
                esac
                echo ""
                # The "auth" options behaves differently with AEAD ciphers
                if [[ $CIPHER =~ CBC$ ]]; then
                        echo "The digest algorithm authenticates data channel packets and tls-auth packets from the control channel."
                elif [[ $CIPHER =~ GCM$ ]]; then
                        echo "The digest algorithm authenticates tls-auth packets from the control channel."
                fi
                echo "Which digest algorithm do you want to use for HMAC?"
                echo "   1) SHA-256 (recommended)"
                echo "   2) SHA-384"
                echo "   3) SHA-512"
                until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
                        read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
                done
                case $HMAC_ALG_CHOICE in
                1)
                        HMAC_ALG="SHA256"
                        ;;
                2)
                        HMAC_ALG="SHA384"
                        ;;
                3)
                        HMAC_ALG="SHA512"
                        ;;
                esac
echo ""
                echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
                echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
                echo "   1) tls-crypt (recommended)"
                echo "   2) tls-auth"
                until [[ $TLS_SIG =~ [1-2] ]]; do
                        read -rp "Control channel additional security mechanism [1-2]: " -e -i 1 TLS_SIG
                done
        fi
        echo ""
        echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
        echo "You will be able to generate a client at the end of the installation."
        APPROVE_INSTALL=${APPROVE_INSTALL:-n}
        if [[ $APPROVE_INSTALL =~ n ]]; then
                read -n1 -r -p "Press any key to continue..."
        fi
}



