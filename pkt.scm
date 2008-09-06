;;;; Lysiane Bouchard - Vincent St-Amour
;;;; filename: pkt.scm

;;;  - packet format
;;;  - some standard constants associated to the different protocols
;;;  - operations on the packet

;; note : there is always only one packet in the system

;; TODO should we keep the current packet's length somewhere ?

;; TODO options are not supported as of now
(define tcp-opt-len 0) ;; TODO are TCP options supported ?
(define data-len 0)


;; packet offsets

;; TODO is there a better way ? what about a slip back-end ?
;; Ethernet header
(define eth-header 0)
(define eth-dst-MAC 0)
(define eth-src-MAC 6)
(define eth-type    12)
(define eth-data    14)

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
(define ip-options  34) ;; TODO not supported as of now

;; TODO everything after ip would have to be functions (because of options that change), instead, let's try to have functions like ip-data-ref, tcp-data-ref, etc that add the offset for us. that is, when weadd options

;; ICMP message
(define icmp-header 34)
(define icmp-type 34)
(define icmp-code 35)
(define icmp-checksum 36)
(define icmp-options 38)
(define icmp-data 42) ; TODO this used to be 4, but now we consider the header to be 8 bytes, with 4 of options, that can be used differently according to each operation

;; TCP header
(define tcp-header       34)
(define tcp-src-portnum  34)
(define tcp-dst-portnum  36)
(define tcp-seqnum       38)
(define tcp-acknum       42)
(define tcp-hdr-len      46)
(define tcp-flags        47)
(define tcp-window       48)
(define tcp-checksum     50)
(define tcp-urgentptr    52)
(define tcp-options      54) ;; TODO do we support options ? looking at these offsets, looks like we don't
(define tcp-data         54)

;; UDP header
(define udp-header      34)
(define udp-src-portnum 34)
(define udp-dst-portnum 36)
(define udp-length      38)
(define udp-checksum    40)
(define udp-data        42)


;; sets vect as the current packet
(define (whole-pkt-set! vect)
  (u8vector-copy! vect 0 pkt 0 (u8vector-length vect)))


;; integer value of a 2 bytes packet subfield
;; TODO why do we return an integer, why not a field ? might be more intuitive, but might be more costly
;; TODO have u8vector-ref-2 instead, maybe not, since integer refs on vectors is used on portnums, but I don't see where else
;; TODO say in the name it returns an int
(define (pkt-ref-2 i)
  (+ (* 256 (u8vector-ref pkt i)) (u8vector-ref pkt (+ i 1))))

;; copies an integer into n contiguous bytes of the packet
;; warning : picobit has 24-bit integers, keep this in mind when n > 3
;; TODO get rid of integer->subfield ? maybe have only one of the 2 ?
(define (integer->pkt val idx n)
  (if (> n 0)
      (begin (u8vector-set! pkt (- (+ idx n) 1) (modulo val 256))
	     (integer->pkt (quotient n 256) idx (- n 1)))))
;; TODO better name, that mentions integer, and a !


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
