;;;; Lysiane Bouchard - Vincent St-Amour
;;;; pkt.scm

;;;  - packet format
;;;  - operations on the packet

;; note : there is always only one packet in the system

;; TODO should we keep the current packet's length somewhere ?

;; TODO options are not supported as of now
(define tcp-options-length 0) ;; TODO are TCP options supported ?
(define data-length 0) ;; TODO any way to pass around instead ?


;; packet offsets

;; TODO is there a better way ? what about a slip back-end ?
;; Ethernet
(define ethernet-header          0)
(define ethernet-destination-mac 0)
(define ethernet-source-mac      6)
(define ethernet-frame-type      12)
(define ethernet-data            14)

;; ARP / RARP
(define arp-header                  14)
(define arp-hardware-type           14)
(define arp-protocol-type           16)
(define arp-hardware-address-length 18)
(define arp-protocol-address-length 19)
(define arp-operation               20)
(define arp-source-hardware-address 22) ;; TODO remove address from the name ?
(define arp-source-ip               28)
(define arp-target-hardware-address 32)
(define arp-target-ip               28)
(define arp-length 28)

;; IP
(define ip-header                    14)
(define ip-version-and-header-length 14)
(define ip-service                   15)
(define ip-length                    16)
(define ip-identification            18)
(define ip-fragment-offset           20)
(define ip-time-to-live              22)
(define ip-protocol                  23) ;; TODO pretty ambiguous name
(define ip-checksum                  24)
(define ip-source-ip                 26)
(define ip-destination-ip            30)
(define ip-options                   34) ;; TODO not supported as of now
(define ip-header-length 20)

;; TODO everything after ip would have to be functions (because of options that change), instead, let's try to have functions like ip-data-ref, tcp-data-ref, etc that add the offset for us. that is, when weadd options

;; ICMP
(define icmp-header   34)
(define icmp-type     34)
(define icmp-code     35)
(define icmp-checksum 36)
(define icmp-options  38)
(define icmp-data     42)
(define icmp-header-length 8) ;; TODO do the same for other protocols ?

;; TCP
(define tcp-header              34)
(define tcp-source-portnum      34)
(define tcp-destination-portnum 36)
(define tcp-seqnum              38) ; TODO change name ?
(define tcp-acknum              42) ; TODO change name ?
(define tcp-header-length       46)
(define tcp-flags               47)
(define tcp-window              48)
(define tcp-checksum            50)
(define tcp-urgent-data-pointer 52)
(define tcp-options             54) ;; TODO do we support options ? looking at these offsets, looks like we don't
(define tcp-data                54)
;; TODO watch out if we want to store the length, not to have the same var name as above

;; UDP
(define udp-header              34)
(define udp-source-portnum      34)
(define udp-destination-portnum 36)
(define udp-length              38)
(define udp-checksum            40)
(define udp-data                42)


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
