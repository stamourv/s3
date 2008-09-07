;;;; Lysiane Bouchard - Vincent St-Amour
;;;; arp.scm

(define arp-operation-request  '#u8(#x00 #x01))
(define arp-operation-response '#u8(#x00 #x02))
(define arp-ethernet-type      '#u8(#x00 #x01))

;; called when an ARP request is received
(define (arp-pkt-in)
  (if (and (u8vector-equal-field? pkt arp-hardware-type arp-ethernet-type 0 2)
 	   (u8vector-equal-field?
	    pkt arp-protocol-type ethernet-frame-type-ipv4 0 2)
 	   (= (u8vector-ref pkt arp-hardware-address-length) 6)
 	   (= (u8vector-ref pkt arp-protocol-address-length) 4)
 	   ;; TODO we really need all these checks ? be liberal in what you accept ?
 	   (u8vector-equal-field? pkt arp-operation arp-operation-request 0 2)
; 	   (or (u8vector-equal-field? pkt arp-target-ip my-ip 0 4)       ; check if we are the target
;	   (u8vector-equal-field? pkt arp-target-ip broadcast-ip 0 4)) ;; TODO bug, even with a broadcast, this doesn't pass
	   ) ;; TODO should we tolerate broadcast ? goes a bit against the spirit of ARP
      (begin
	(debug "arp\n")
	(u8vector-copy! arp-operation-response 0 pkt arp-operation 2) ; ARP response
	(u8vector-copy! pkt arp-source-hardware-address
			pkt arp-target-hardware-address 6)
	(u8vector-copy! pkt arp-source-ip pkt arp-target-ip 4) ;; TODO maybe a function to swap source ip and mac with the target, etc, and put our own info when we answer ?
 	(u8vector-copy! my-mac 0 pkt arp-source-hardware-address 6)
	(u8vector-copy! my-ip 0 pkt arp-source-ip 4)
	(ethernet-encapsulation arp-length))
      #f))
