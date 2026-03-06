#!/bin/bash
###############################################################################
#  bsec_status.sh — STM32MP25x BSEC OTP Decoder (RM0457)
#
#  Reads OTP fuse words via NVMEM (OP-TEE) and decodes known fields:
#  lifecycle, device ID, package, keys, board info, MAC address, etc.
#
#  Usage:  sudo ./bsec_status.sh [NVMEM_DEVICE]
#          Default device: stm32-romem0
#
###############################################################################

set -euo pipefail

# ── configuration ────────────────────────────────────────────────────────────
NVMEM_DEV="${1:-stm32-romem0}"
NVMEM_PATH="/sys/bus/nvmem/devices/${NVMEM_DEV}/nvmem"

# ── colours ──────────────────────────────────────────────────────────────────
RST="\033[0m"
BOLD="\033[1m"
RED="\033[1;31m"
GRN="\033[1;32m"
YEL="\033[1;33m"
BLU="\033[1;34m"
MAG="\033[1;35m"
CYN="\033[1;36m"
WHT="\033[1;37m"
DIM="\033[2m"
BG_RED="\033[41m"
BG_GRN="\033[42m"
BG_YEL="\033[43m"
BG_BLU="\033[44m"

# ── sanity checks ────────────────────────────────────────────────────────────
if [ ! -f "$NVMEM_PATH" ]; then
    echo -e "${RED}ERROR:${RST} NVMEM device not found at $NVMEM_PATH" >&2
    echo "" >&2
    echo "Available NVMEM devices:" >&2
    ls /sys/bus/nvmem/devices/ 2>/dev/null || echo "  (none)" >&2
    exit 1
fi

# ── read full dump into temp file ────────────────────────────────────────────
TMPFILE=$(mktemp /tmp/bsec_decode.XXXXXX)
trap "rm -f $TMPFILE" EXIT

dd if="$NVMEM_PATH" of="$TMPFILE" bs=1 2>/dev/null
FILESIZE=$(stat -c%s "$TMPFILE" 2>/dev/null || stat -f%z "$TMPFILE" 2>/dev/null)
TOTAL_WORDS=$((FILESIZE / 4))

# ── helpers ──────────────────────────────────────────────────────────────────
read_word() {
    local word_idx=$1
    local offset=$((word_idx * 4))
    if [ $offset -ge $FILESIZE ]; then
        echo 0
        return
    fi
    local hex
    hex=$(dd if="$TMPFILE" bs=1 skip=$offset count=4 2>/dev/null | \
          od -A n -t x4 --endian=little | tr -d ' \n')
    printf "%d" "0x${hex}" 2>/dev/null || echo 0
}

read_word_hex() {
    local word_idx=$1
    local offset=$((word_idx * 4))
    if [ $offset -ge $FILESIZE ]; then
        echo "00000000"
        return
    fi
    dd if="$TMPFILE" bs=1 skip=$offset count=4 2>/dev/null | \
        od -A n -t x4 --endian=little | tr -d ' \n' || echo "00000000"
}

read_bytes_ascii() {
    local offset=$1
    local count=$2
    dd if="$TMPFILE" bs=1 skip=$offset count=$count 2>/dev/null | \
        tr -cd '[:print:]'
}

read_bytes_hex() {
    local offset=$1
    local count=$2
    dd if="$TMPFILE" bs=1 skip=$offset count=$count 2>/dev/null | \
        od -A n -t x1 | tr -d '\n' | sed 's/  */ /g; s/^ //'
}

bit() {
    echo $(( ($1 >> $2) & 1 ))
}

bits() {
    echo $(( ($1 >> $2) & ((1 << $3) - 1) ))
}

section() {
    echo ""
    echo -e "${BG_BLU}${WHT}  $1  ${RST}"
    echo -e "${BLU}$(printf '~%.0s' $(seq 1 70))${RST}"
}

subsection() {
    echo -e "  ${CYN}> $1${RST}"
}

val_line() {
    printf "    ${WHT}%-24s${RST} : ${BOLD}%s${RST}\n" "$1" "$2"
}

val_line_color() {
    printf "    ${WHT}%-24s${RST} : %b\n" "$1" "$2"
}

hex_block() {
    local label="$1"
    local start_word=$2
    local count=$3
    local offset=$((start_word * 4))
    local bytes=$((count * 4))
    local hex
    hex=$(dd if="$TMPFILE" bs=1 skip=$offset count=$bytes 2>/dev/null | \
          od -A n -t x1 | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//')
    printf "    ${WHT}%-24s${RST} : ${DIM}%s${RST}\n" "$label" "$hex"
}

check_all_zero() {
    local start_word=$1
    local count=$2
    local offset=$((start_word * 4))
    local bytes=$((count * 4))
    # Read raw bytes, check if any are non-zero using tr to strip null bytes
    local nonzero
    nonzero=$(dd if="$TMPFILE" bs=1 skip=$offset count=$bytes 2>/dev/null | \
              tr -d '\000')
    [ -z "$nonzero" ] && echo 1 || echo 0
}

# ── banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BG_BLU}${WHT}                                                                      ${RST}"
echo -e "${BG_BLU}${WHT}    ######   ######  ########  ######     OTP Decoder                 ${RST}"
echo -e "${BG_BLU}${WHT}    ##   ##  ##      ##       ##          STM32MP25x (RM0457)          ${RST}"
echo -e "${BG_BLU}${WHT}    ######   #####   #####    ##          $(date '+%Y-%m-%d %H:%M:%S')             ${RST}"
echo -e "${BG_BLU}${WHT}    ##   ##      ##  ##       ##          via NVMEM / OP-TEE           ${RST}"
echo -e "${BG_BLU}${WHT}    ######  ######   ########  ######                                  ${RST}"
echo -e "${BG_BLU}${WHT}                                                                      ${RST}"
echo ""
echo -e "  ${DIM}NVMEM path : $NVMEM_PATH${RST}"
echo -e "  ${DIM}OTP words  : $TOTAL_WORDS ($FILESIZE bytes)${RST}"
echo -e "  ${DIM}Access     : Linux -> sysfs NVMEM -> OP-TEE BSEC PTA -> fuse array${RST}"

###############################################################################
#  1. LIFECYCLE (Words 0–3)
###############################################################################
section "1. LIFECYCLE & BSEC CONFIGURATION"

W0=$(read_word 0);  W0H=$(read_word_hex 0)
W1=$(read_word 1);  W1H=$(read_word_hex 1)
W2=$(read_word 2);  W2H=$(read_word_hex 2)
W3=$(read_word 3);  W3H=$(read_word_hex 3)

val_line "OTP Word 0 (config)" "0x$W0H"
val_line "OTP Word 1 (lifecycle)" "0x$W1H"
val_line "OTP Word 2 (RMA counter)" "0x$W2H"
val_line "OTP Word 3" "0x$W3H"

echo ""
subsection "Lifecycle Analysis (Word 1)"

# s[7:0] from Word 1 nibbles — each nibble OR'd to one bit
S7=$(( ( ($W1 >> 28) & 0xF ) > 0 ? 1 : 0 ))
S6=$(( ( ($W1 >> 24) & 0xF ) > 0 ? 1 : 0 ))
S5=$(( ( ($W1 >> 20) & 0xF ) > 0 ? 1 : 0 ))
S4=$(( ( ($W1 >> 16) & 0xF ) > 0 ? 1 : 0 ))
S3=$(( ( ($W1 >> 12) & 0xF ) > 0 ? 1 : 0 ))
S2=$(( ( ($W1 >>  8) & 0xF ) > 0 ? 1 : 0 ))
S1=$(( ( ($W1 >>  4) & 0xF ) > 0 ? 1 : 0 ))
S0=$(( ( ($W1 >>  0) & 0xF ) > 0 ? 1 : 0 ))
SVAL=$(( (S7<<7) | (S6<<6) | (S5<<5) | (S4<<4) | (S3<<3) | (S2<<2) | (S1<<1) | S0 ))

# r[7:0] from Word 2 nibbles — each nibble AND'd to one bit
R7=$(( ( ($W2 >> 28) & 0xF ) == 0xF ? 1 : 0 ))
R6=$(( ( ($W2 >> 24) & 0xF ) == 0xF ? 1 : 0 ))
R5=$(( ( ($W2 >> 20) & 0xF ) == 0xF ? 1 : 0 ))
R4=$(( ( ($W2 >> 16) & 0xF ) == 0xF ? 1 : 0 ))
R3=$(( ( ($W2 >> 12) & 0xF ) == 0xF ? 1 : 0 ))
R2=$(( ( ($W2 >>  8) & 0xF ) == 0xF ? 1 : 0 ))
R1=$(( ( ($W2 >>  4) & 0xF ) == 0xF ? 1 : 0 ))
R0=$(( ( ($W2 >>  0) & 0xF ) == 0xF ? 1 : 0 ))
RVAL=$(( (R7<<7) | (R6<<6) | (R5<<5) | (R4<<4) | (R3<<3) | (R2<<2) | (R1<<1) | R0 ))

val_line "  s[7:0] (close counter)" "0x$(printf '%02X' $SVAL)  (binary: $S7$S6$S5$S4$S3$S2$S1$S0)"
val_line "  r[7:0] (open counter)" "0x$(printf '%02X' $RVAL)  (binary: $R7$R6$R5$R4$R3$R2$R1$R0)"

if [ $SVAL -gt $RVAL ] || [ $S7 -eq 1 ]; then
    val_line_color "  Derived state" "${GRN}BSEC-CLOSED  (s > r or s[7]=1)${RST}"
else
    val_line_color "  Derived state" "${YEL}BSEC-OPEN  (s <= r and s[7]=0)${RST}"
fi

# Re-open attempts
if [ $S7 -eq 1 ]; then
    val_line_color "  Re-open attempts left" "${RED}0 (permanently closed, s[7]=1)${RST}"
elif [ $S6 -eq 1 ]; then
    val_line_color "  Re-open attempts left" "${YEL}1 (s[6]=1, only one attempt)${RST}"
else
    # Count used nibbles in Word 2
    USED=0
    for shift in 0 4 8 12 16 20 24 28; do
        nibble=$(( ($W2 >> shift) & 0xF ))
        [ $nibble -ne 0 ] && USED=$((USED + 1))
    done
    REMAINING=$((4 - USED))
    [ $REMAINING -lt 0 ] && REMAINING=0
    val_line_color "  Re-open attempts left" "${CYN}$REMAINING of 4${RST}"
fi

###############################################################################
#  2. DEVICE IDENTIFICATION
###############################################################################
section "2. DEVICE IDENTIFICATION"

W5=$(read_word 5);  W5H=$(read_word_hex 5)
W6=$(read_word 6);  W6H=$(read_word_hex 6)
W7=$(read_word 7);  W7H=$(read_word_hex 7)
W9=$(read_word 9);  W9H=$(read_word_hex 9)
W10=$(read_word 10); W10H=$(read_word_hex 10)

subsection "Serial Number (Word 5)"
val_line "OTP Word 5" "0x$W5H"

echo ""
subsection "Wafer / Lot ID (Words 6-7)"
LOT_ASCII=$(read_bytes_ascii $((6*4)) 8)
val_line "OTP Words 6-7 (raw)" "0x$W6H  0x$W7H"
val_line "ASCII content" "\"$LOT_ASCII\""

echo ""
subsection "Device Part Number — RPN (Word 9)"
val_line "OTP Word 9 (raw)" "0x$W9H"

# Try to decode RPN bits (device-specific)
RPN_UPPER=$(( ($W9 >> 16) & 0xFFFF ))
RPN_LOWER=$(( $W9 & 0xFFFF ))
val_line "  Bits [31:16]" "0x$(printf '%04X' $RPN_UPPER)"
val_line "  Bits [15:0]" "0x$(printf '%04X' $RPN_LOWER)"

echo ""
subsection "Version / Revision (Word 10)"
val_line "OTP Word 10 (raw)" "0x$W10H"

###############################################################################
#  3. PACKAGE INFO (Word 122)
###############################################################################
section "3. PACKAGE INFO (Word 122)"

W122=$(read_word 122); W122H=$(read_word_hex 122)
PKG=$(( $W122 & 0x7 ))

val_line "OTP Word 122 (raw)" "0x$W122H"
val_line "Package [bits 2:0]" "$PKG"

case $PKG in
    0) val_line_color "  Package type" "${DIM}Not programmed / unknown${RST}" ;;
    1) val_line_color "  Package type" "${CYN}TFBGA 361+25${RST}" ;;
    2) val_line_color "  Package type" "${CYN}TFBGA 257+25${RST}" ;;
    3) val_line_color "  Package type" "${CYN}TFBGA 196+25${RST}" ;;
    *) val_line_color "  Package type" "${YEL}Code $PKG (check datasheet)${RST}" ;;
esac

###############################################################################
#  4. SECURITY CONFIG (Word 124)
###############################################################################
section "4. SECURITY CONFIGURATION (Word 124)"

W124=$(read_word 124); W124H=$(read_word_hex 124)

val_line "OTP Word 124 (raw)" "0x$W124H"

BIT20=$(bit $W124 20)
if [ $BIT20 -eq 1 ]; then
    val_line_color "  Bit 20 (ST eng. modes)" "${GRN}BLOWN — ST engineering modes disabled in closed state${RST}"
else
    val_line_color "  Bit 20 (ST eng. modes)" "${YEL}NOT blown — ST engineering modes available${RST}"
fi

###############################################################################
#  5. CRYPTOGRAPHIC KEYS / HASHES (lower OTP area)
###############################################################################
section "5. CRYPTOGRAPHIC DATA IN LOWER OTP"

subsection "ST Public Key Area (Words 120-127)"
for w in $(seq 120 127); do
    wh=$(read_word_hex $w)
    if [ "$wh" != "00000000" ]; then
        printf "    ${WHT}Word %-3d${RST} : ${MAG}0x%s${RST}\n" "$w" "$wh"
    else
        printf "    ${WHT}Word %-3d${RST} : ${DIM}0x%s${RST}\n" "$w" "$wh"
    fi
done

###############################################################################
#  6. MIDDLE OTP — RoT KEYS HASHES (Words 128–255)
###############################################################################
section "6. MIDDLE OTP — ROOT OF TRUST DATA (Words 128-255)"

subsection "Scanning for non-zero blocks..."
echo ""

FOUND_DATA=0
BLOCK_START=-1
for w in $(seq 128 255); do
    wh=$(read_word_hex $w)
    if [ "$wh" != "00000000" ]; then
        if [ $BLOCK_START -eq -1 ]; then
            BLOCK_START=$w
        fi
        FOUND_DATA=1
    else
        if [ $BLOCK_START -ne -1 ]; then
            BLOCK_END=$((w - 1))
            BLOCK_LEN=$((BLOCK_END - BLOCK_START + 1))
            BLOCK_BITS=$((BLOCK_LEN * 32))
            echo -e "    ${MAG}Words $BLOCK_START-$BLOCK_END ($BLOCK_LEN words = $BLOCK_BITS bits):${RST}"
            for bw in $(seq $BLOCK_START $BLOCK_END); do
                bwh=$(read_word_hex $bw)
                printf "      ${DIM}[%3d]${RST} 0x%s\n" "$bw" "$bwh"
            done
            echo ""

            if [ $BLOCK_BITS -eq 256 ]; then
                echo -e "      ${YEL}^ Likely a 256-bit SHA-256 hash (public key hash?)${RST}"
            elif [ $BLOCK_BITS -eq 512 ]; then
                echo -e "      ${YEL}^ Likely a 512-bit hash or key block${RST}"
            fi
            echo ""
            BLOCK_START=-1
        fi
    fi
done

# Handle block that extends to end
if [ $BLOCK_START -ne -1 ]; then
    BLOCK_END=255
    BLOCK_LEN=$((BLOCK_END - BLOCK_START + 1))
    echo -e "    ${MAG}Words $BLOCK_START-$BLOCK_END ($BLOCK_LEN words):${RST}"
    for bw in $(seq $BLOCK_START $BLOCK_END); do
        bwh=$(read_word_hex $bw)
        printf "      ${DIM}[%3d]${RST} 0x%s\n" "$bw" "$bwh"
    done
    echo ""
fi

if [ $FOUND_DATA -eq 0 ]; then
    echo -e "    ${DIM}(all zeros — no keys/hashes provisioned in middle OTP)${RST}"
fi

###############################################################################
#  7. UPPER OTP CHECK (Words 256–367)
###############################################################################
section "7. UPPER OTP CHECK (Words 256-367)"

if [ $TOTAL_WORDS -gt 256 ]; then
    ALL_ZERO=$(check_all_zero 256 $((TOTAL_WORDS - 256)))
    if [ "$ALL_ZERO" -eq 1 ]; then
        echo -e "    ${YEL}All upper OTP words read as 0x00000000${RST}"
        echo -e "    ${DIM}This is expected in BSEC-open state — upper fuses are hidden by hardware.${RST}"
        echo -e "    ${DIM}In BSEC-closed state, these would contain secrets (symmetric keys, etc.)${RST}"
    else
        echo -e "    ${RED}Non-zero data found in upper OTP!${RST}"
        echo -e "    ${DIM}This means either the device is BSEC-closed, or some data leaked.${RST}"
        for w in $(seq 256 $((TOTAL_WORDS - 1))); do
            wh=$(read_word_hex $w)
            if [ "$wh" != "00000000" ]; then
                printf "    ${RED}[%3d]${RST} 0x%s\n" "$w" "$wh"
            fi
        done
    fi
else
    echo -e "    ${DIM}(upper OTP not available in this NVMEM dump)${RST}"
fi

###############################################################################
#  8. BOARD IDENTIFICATION (ST boards: Words 246-247)
###############################################################################
section "8. BOARD IDENTIFICATION (ST boards)"

W246=$(read_word 246); W246H=$(read_word_hex 246)
W247=$(read_word 247); W247H=$(read_word_hex 247)

subsection "Board Identifier (Word 246)"
val_line "OTP Word 246 (raw)" "0x$W246H"
if [ "$W246H" != "00000000" ]; then
    val_line_color "  Status" "${GRN}Board ID programmed${RST}"
else
    val_line_color "  Status" "${DIM}Not programmed (virgin)${RST}"
fi

echo ""
subsection "MAC Address Data (Word 247+)"
val_line "OTP Word 247 (raw)" "0x$W247H"

if [ "$W247H" != "00000000" ]; then
    # MAC bytes from OTP 247 (first 3 bytes) + OTP 248 (next 3 bytes)
    W248H=$(read_word_hex 248)
    MAC_RAW="${W247H}${W248H}"
    # Extract individual bytes (little-endian words, so byte order within word is reversed)
    B0=$(echo $W247H | cut -c7-8)
    B1=$(echo $W247H | cut -c5-6)
    B2=$(echo $W247H | cut -c3-4)
    B3=$(echo $W247H | cut -c1-2)
    B4=$(echo $W248H | cut -c7-8)
    B5=$(echo $W248H | cut -c5-6)
    echo -e "    ${WHT}MAC (candidate)${RST}          : ${BOLD}$B0:$B1:$B2:$B3:$B4:$B5${RST}"
    echo -e "    ${DIM}Note: actual MAC extraction depends on board DT config${RST}"
fi

###############################################################################
#  9. CALIBRATION & MISC DATA
###############################################################################
section "9. CALIBRATION & MISC DATA"

subsection "Scanning lower OTP for non-zero words (excluding already decoded)..."
echo ""

KNOWN_WORDS="0 1 2 3 5 6 7 9 10 120 121 122 123 124 125 126 127"

for w in $(seq 4 119); do
    # Skip already decoded
    SKIP=0
    for k in $KNOWN_WORDS; do
        [ "$w" -eq "$k" ] && SKIP=1 && break
    done
    [ $SKIP -eq 1 ] && continue

    wh=$(read_word_hex $w)
    if [ "$wh" != "00000000" ]; then
        printf "    ${WHT}Word %-3d${RST} (offset 0x%03X) : ${CYN}0x%s${RST}\n" "$w" "$((w * 4))" "$wh"
    fi
done

###############################################################################
#  10. OTP USAGE SUMMARY
###############################################################################
section "10. OTP USAGE SUMMARY"

NONZERO_LOWER=0
NONZERO_MIDDLE=0
NONZERO_UPPER=0

for w in $(seq 0 127); do
    wh=$(read_word_hex $w)
    [ "$wh" != "00000000" ] && NONZERO_LOWER=$((NONZERO_LOWER + 1))
done

for w in $(seq 128 255); do
    wh=$(read_word_hex $w)
    [ "$wh" != "00000000" ] && NONZERO_MIDDLE=$((NONZERO_MIDDLE + 1))
done

if [ $TOTAL_WORDS -gt 256 ]; then
    for w in $(seq 256 $((TOTAL_WORDS - 1))); do
        wh=$(read_word_hex $w)
        [ "$wh" != "00000000" ] && NONZERO_UPPER=$((NONZERO_UPPER + 1))
    done
    UPPER_TOTAL=$((TOTAL_WORDS - 256))
else
    UPPER_TOTAL=0
fi

echo ""
printf "    ${WHT}%-30s${RST}  ${BOLD}%3d / 128${RST}  words used\n" \
    "Lower  OTP (0-127)" "$NONZERO_LOWER"
printf "    ${WHT}%-30s${RST}  ${BOLD}%3d / 128${RST}  words used\n" \
    "Middle OTP (128-255)" "$NONZERO_MIDDLE"
if [ $UPPER_TOTAL -gt 0 ]; then
    printf "    ${WHT}%-30s${RST}  ${BOLD}%3d / %-3d${RST}  words visible\n" \
        "Upper  OTP (256-$((TOTAL_WORDS-1)))" "$NONZERO_UPPER" "$UPPER_TOTAL"
fi

echo ""
TOTAL_USED=$((NONZERO_LOWER + NONZERO_MIDDLE + NONZERO_UPPER))
echo -e "    Total non-zero words: ${BOLD}$TOTAL_USED / $TOTAL_WORDS${RST}"

# Visual bar
BAR_WIDTH=50
BAR_FILLED=$(( TOTAL_USED * BAR_WIDTH / TOTAL_WORDS ))
[ $BAR_FILLED -eq 0 ] && [ $TOTAL_USED -gt 0 ] && BAR_FILLED=1
BAR_EMPTY=$((BAR_WIDTH - BAR_FILLED))

printf "    ["
printf "${GRN}"
for i in $(seq 1 $BAR_FILLED); do printf "#"; done
printf "${DIM}"
for i in $(seq 1 $BAR_EMPTY); do printf "."; done
printf "${RST}] %d%%\n" "$((TOTAL_USED * 100 / TOTAL_WORDS))"

###############################################################################
#  Done
###############################################################################
echo ""
echo -e "${BG_GRN}${WHT}  DONE — BSEC OTP decode complete  ${RST}"
echo ""
echo -e "${DIM}Notes:${RST}"
echo -e "${DIM}  - Upper OTP (256+) are hidden in BSEC-open state (by hardware design)${RST}"
echo -e "${DIM}  - BSEC status registers (BSEC_SR, BSEC_DENR, locks) are NOT accessible${RST}"
echo -e "${DIM}    via NVMEM — they require direct register access from secure world${RST}"
echo -e "${DIM}  - Access path: Linux -> sysfs NVMEM -> OP-TEE BSEC PTA -> fuse array${RST}"
echo ""