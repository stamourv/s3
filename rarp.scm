;;;; Vincent St-Amour
;;;; rarp.scm

(define rarp-operation-request  '#u8(#x00 #x03))
(define rarp-operation-response '#u8(#x00 #x04))
(define rarp-ethernet-type      '#u8(#x00 #x01))

;; called when a RARP request is received
(define (rarp-pkt-in)
  ;; most constants are the same as ARP, due to the similarity of the 2
  ;; protocols
  (if (and (u8vector-equal-field? pkt arp-hardware-type rarp-ethernet-type 0 2)
	   (u8vector-equal-field?
	    pkt arp-protocol-type ethernet-frame-type-ipv4 0 2)
	   (= (u8vector-ref pkt arp-hardware-address-length) 6)
	   (= (u8vector-ref pkt arp-protocol-address-length) 4)
	   (u8vector-equal-field? pkt arp-operation rarp-operation-request 0 2))
      ;; TODO part of this validation is common with arp, abstract ?
      ;; no need to check if we are the target or not, RARP requests are
      ;; broadcast
      (begin
	(u8vector-copy! rarp-operation-response 0 pkt arp-operation 2) ; RARP response
	;; TODO abstract the following with ARP ?
	(u8vector-copy! pkt arp-target-hardware-address
			pkt arp-source-hardware-address 6) ;; TODO make sure this is ok
	(u8vector-copy! (rarp-get-ip) 0 pkt arp-target-ip 4)
	(u8vector-copy! my-mac 0 pkt arp-source-hardware-address 6)
	(u8vector-copy! my-ip 0 pkt arp-source-ip 4) ;; TODO abstract similarities between arp and rarp
	(ethernet-encapsulation arp-length))
      #f))

(define (rarp-get-ip)
  (cdr (assoc (u8vector-ref-field pkt arp-source-hardware-address 6)
	      rarp-mac-ip-alist)))
