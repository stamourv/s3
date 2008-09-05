;;;; Lysiane Bouchard - Vincent St-Amour
;;;; filename: pkt.scm

;;;  - packet format
;;;  - some standard constants associated to the different protocols
;;;  - operations on the packet

;; note : there is always only one packet in the system

;; TODO should we keep the current packet's length somewhere ?

;; TODO options are not supported as of now
(define ip-opt-len 0) ; length of ip options for this particular packet
(define tcp-opt-len 0)
(define data-len 0)


;; packet offsets

;; TODO is there a better way ? what about a slip back-end ?
;; Ethernet header
(define eth-header 0)
(define eth-dst-MAC 0)
(define eth-src-MAC 6)
(define eth-type    12)
(define eth-data    14)
(define (eth-offset n) (+ eth-data n))

;; ARP header
(define arp-header 14)
(define arp-htype  14)
(define arp-ptype  16)
(define arp-halen  18)
(define arp-palen  19)
(define arp-oper   20)
(define arp-shadr  22)
(define arp-sip    28)
(define arp-thadr  32)
(define arp-tip    28)
(define arp-end    42)
(define arp-length 28)

;; IP header
(define ip-header   14)
(define ip-version  14)
(define ip-hdr-len  14)
(define ip-service  15)
(define ip-length   16)
(define ip-ident    18)
(define ip-frag     20)
(define ip-ttl      22)
(define ip-protocol 23) ;; TODO pretty ambiguous name
(define ip-checksum 24)
(define ip-src-IP   26)
(define ip-dst-IP   30)
(define ip-options  34)
(define (ip-offset n) (+ ip-options ip-opt-len n)) ;; TODO what about options ? added them, but they weren't counted originally (actually, they were added by pkt-ref, which was horribly ugly, got rid of that, and that cleaned a few other things as well)

;; TODO everything after ip would have to be functions (because of options that change), instead, let's try to have functions like ip-data-ref, tcp-data-ref, etc that add the offset for us

;; ICMP message
(define icmp-type 34) ;; TODO no options are considered
(define icmp-code 35)
(define icmp-checksum 36)
(define icmp-options 38)
(define icmp-data 42) ; TODO this used to be 4, but now we consider the header to be 8 bytes, with 4 of options, that can be used differently according to each operation
(define (icmp-offset i) (+ i icmp-data)) ;; TODO maybe a macro ? this pattern appears quite often
;; TODO are these offset functions used at all ?

;; TCP header
(define tcp-header       34) ;; TODO should all these be function ? their value might change due to the value of option lengths
(define tcp-src-portnum  34)
(define tcp-dst-portnum  36)
(define tcp-seqnum       38)
(define tcp-acknum       42)
(define tcp-hdr-len      46)
(define tcp-flags        47)
(define tcp-window       48)
(define tcp-checksum     50)
(define tcp-urgentptr    52)
(define tcp-options      54)
(define (tcp-offset n)   (+ tcp-options tcp-opt-len n))
(define (tcp-data-start) 54) ;; TODO function ? a vlaue could be ok, I guess

;; UDP header
(define udp-header      34)
(define udp-src-portnum 34)
(define udp-dst-portnum 36)
(define udp-length      38)
(define udp-checksum    40)
(define udp-data        42)
(define (udp-offset i)  (+ i udp-data))


;; sets vect as the current packet, but keeps the original size, in the case we
;; have a response longer than the original message
;; TODO there's a similar function in the original tests, use it instead ?
(define (whole-pkt-set! vect)
  (u8vector-copy! vect 0 pkt 0 (u8vector-length vect)))


;; integer value of a 2 bytes packet subfield
;; TODO why do we return an integer, why not a field ? might be more intuitive, but might be more costly
;; TODO have u8vector-ref-2 instead
(define (pkt-ref-2 i)
  (+ (* 256 (u8vector-ref pkt i)) (u8vector-ref pkt (+ i 1))))


;; TODO eventually use this instead of pkt-ref-n
(define (pkt-ref-field-n i n) (u8vector-ref-field pkt i n)) ;; TODO be a simple call to the general ref-field
(define (pkt-ref-field-2 i) (pkt-ref-field-n i 2))
(define (pkt-ref-field-4 i) (pkt-ref-field-n i 4)) ;; TODO used once
(define (pkt-ref-field-6 i) (pkt-ref-field-n i 6)) ;; TODO used once


;; copies data from a subfield to the packet (n = subfield length)
(define (copy-subfield->pkt-n src i-src i-pkt n)
  (u8vector-copy! src i-src pkt i-pkt n))
;; TODO is it really necessary to have a function for that ? NO, get rid, inline

;; idem, but the subfield begins at the first element of a u8vector
(define (copy-u8->pkt-n i u8 n) ;; TODO weird argument order
  (copy-subfield->pkt-n u8 0 i n))
(define (copy-u8->pkt-2 i u8) (copy-u8->pkt-n i u8 2))
(define (copy-u8->pkt-4 i u8) (copy-u8->pkt-n i u8 4))
(define (copy-u8->pkt-6 i u8) (copy-u8->pkt-n i u8 6))
;; TODO call these a name with set! ? would be clearer

;; copies data from pkt to a subfield
(define (copy-pkt->subfield-n i-pkt dst i-dst n)
  (u8vector-copy! pkt i-pkt dst i-dst n))


;; copies an integer into n contiguous bytes of the packet
;; warning : picobit has 24-bit integers, keep this in mind when n > 3
;; TODO get rid of integer->subfield ? maybe have only one of the 2 ?
(define (integer->pkt-n val idx n) (integer->subfield val pkt idx n))
(define (integer->pkt-2 val idx) (integer->subfield val pkt idx 2))

;; compares a subfield to a packet subfield
(define (=pkt-byte? i x) (= (u8vector-ref pkt i) x))
(define (=subfield-pkt-n? pkt-i object start n)
  (u8vector-equal-field? pkt pkt-i object start n))

;; idem, but the subfield is a u8vector subfield and begins at the first element
;; TODO do we really need both ?
;; TODO get rid of these, superfluous function calls
(define (=pkt-u8-n? i u8 n) (=subfield-pkt-n? i u8 0 n))
(define (=pkt-u8-6? i u8) (=pkt-u8-n? i u8 6))
(define (=pkt-u8-4? i u8) (=pkt-u8-n? i u8 4))
(define (=pkt-u8-2? i u8) (=pkt-u8-n? i u8 2))
;; TODO pass the true vectors around instead of functions ?

;; to move n consecutive bytes from "orig" in pkt to "dest"
;; TODO doesn't work, should replace translate-in-pkt
; (define (move-in-pkt-n src dst n)
;   (let ((move-in-pkt (lambda (i val) (pkt-set! (+ i (- dst src)) val)))) ; TODO can we do without this subtraction ?
;     (copy-pkt->subfield-n src move-in-pkt src n)))
(define (move-in-pkt-n src dst n)
  (copy-pkt->subfield-n src pkt dst n)) ;; TODO ugly, get rid
;; TODO this might be the reason we start at he end in vector-something, if not, make sure we don't clobber anything
