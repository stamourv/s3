;;;; Lysiane Bouchard - Vincent St-Amour
;;;; tcp.scm

;; TODO say what's really in here
;;;  - tcp state functions
;;;  - procedure called when a TCP packet is received:
;;;    see "tcp-pkt-in"


;; specific manipulations of some subfields
(define (get-tcp-flags) (modulo (u8vector-ref pkt tcp-flags) 64))


;; called when a TCP packet is received
(define (tcp-pkt-in)
  ;; 40 is the sum of the sizesof the IP and TCP headers
  (set! data-length (- (pkt-ref-2 ip-length) 40))
  (cond ((not (= (u8vector-ref pkt tcp-header-length-offset) 80)) ;; TODO have this 80 in a variable ?
	 ;; the packet has TCP options (header longer than 20 bytes), we reject
	 ;; it. since the length is then always 20 bytes, followed by 4 reserved
	 ;; bits (which must be set to 0), we simply must check if the byte is
	 ;; equal to (20 / 4) << 4 = 80
	 #f))
  (if (or (= (pkt-ref-2 tcp-checksum) 0) ; valid or no checksum ?
	  (= 65535 (compute-tcp-checksum)))
      (let ((port (search-port
		   (pkt-ref-2 tcp-destination-portnum)
		   tcp-ports)))
	(if (and port (pass-app-filter? tcp-source-portnum port))
	    (begin
	      (set! curr-port port)
	      (let ((target-connection
		     (memp (lambda (c)
			     (and (=conn-info-pkt? tcp-source-portnum c conn-peer-portnum 2)
				  (=conn-info-pkt? ip-source-ip c conn-peer-ip 4)
				  (=conn-info-pkt? ip-destination-ip c conn-self-ip 4)))
			   (get-curr-conns))))
		(if target-connection
		    (begin (set! curr-conn target-connection)
			   ;; call the current state function TODO which sets a new one in the structure ? make sure
			   ((vector-ref target-connection conn-state-function)))
		    ;; no matching connection was found, if we have not yet
		    ;; reached the maximum number of connections, establish a
		    ;; new one
		    (if (and (< (length (get-curr-conns)) ;; TODO this actually was a state function (tcp-listen)
				(conf-ref curr-port conf-max-conns))
			     ;; the handshake must begin with a SYN
			     (exclusive-tcp-flag? SYN))
			(begin (new-conn) ; this sets the new connection as the current one
			       (self-acknowledgement) ;; TODO was in the call to transferts controller, but does it make any sense ?
			       (increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
			       (pass-to-another-state tcp-syn-recv)
			       (tcp-transfers-controller (+ SYN ACK) #f #f))))))
	    (icmp-unreachable icmp-port-unreachable)))))


(define (compute-tcp-checksum)
  (pkt-checksum
   ip-source-ip
   ;; the UDP pseudo-header uses values located before the TCP header
   (+ ip-header (pkt-ref-2 ip-length)) ; end of the TCP data
   ;; start with the values of the pseudo-header that are not adjacent to the
   ;; rest of the pseudo-header
   (add-16bits-1comp 6 ; TCP protocol ID, with leading zeroes up to 16 bits
		     (- (pkt-ref-2 ip-length) ip-header-length)))) ; TCP length



;;----------tcp state functions --------------------------------------------


;; each one of those function garanties the behaviour of
;; the tcp protocol according to a specific standard tcp state.

;; tcp state time-wait
(define (tcp-time-wait)
  (tcp-state-function (lambda () #t)))

;; tcp state fin-wait-2
(define (tcp-fin-wait-2)
  (tcp-state-function
   (lambda () (if (inclusive-tcp-flag? FIN)
		  (begin (increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
			 (pass-to-another-state tcp-time-wait)
			 (tcp-transfers-controller ACK #t #f))
		  (tcp-transfers-controller 0 #t #f)))))


;; tcp state closing
(define (tcp-closing)
  (tcp-state-function
   (lambda () (if (and (inclusive-tcp-flag? ACK)
		       (valid-acknum?))
		  (begin (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
			 (pass-to-another-state tcp-time-wait)
			 (tcp-transfers-controller ACK #f #f))))))


;; tcp state fin-wait-1
(define (tcp-fin-wait-1)
  (tcp-state-function
   (lambda ()
     (if (inclusive-tcp-flag? FIN)
	 (begin
	   (if (and (inclusive-tcp-flag? ACK)
		    (valid-acknum?))
	       (begin (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
		      (increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
		      (pass-to-another-state tcp-time-wait))
	       (begin (increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
		      (pass-to-another-state tcp-closing)))
	   (tcp-transfers-controller ACK #t #f)) ;; TODO make sure this does what we want
	 (begin (if (and (inclusive-tcp-flag? ACK)
			 (valid-acknum?))
		    (begin (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
			   (pass-to-another-state tcp-fin-wait-2)))
		(tcp-transfers-controller 0 #t #f))))))


;; tcp state last-ack
(define (tcp-last-ack)
  (tcp-state-function
   (lambda () (if (and (inclusive-tcp-flag? ACK)
		       (valid-acknum?))
		  (tcp-end)))))


;; tcp state close-wait
(define (tcp-close-wait)
  (tcp-state-function
   (lambda ()
     (if (and (inclusive-tcp-flag? ACK) (valid-acknum?))
	 (self-acknowledgement))
     (tcp-transfers-controller 0 #f #t))))


;; tcp state established
(define (tcp-established)
  (tcp-state-function
   (lambda ()
     (if (and (inclusive-tcp-flag? ACK) (valid-acknum?))
	 ;; we have received an ACK, we can consume the data that was
	 ;; acknowledged
	 (buf-consume (vector-ref curr-conn conn-output)
		      (self-acknowledgement)))
     (if (inclusive-tcp-flag? FIN)
	 (begin (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
		(increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
		(pass-to-another-state tcp-close-wait)
		(tcp-transfers-controller ACK #t #t))
	 (tcp-transfers-controller 0 #t #t)))))

;; tcp state syn-received
(define (tcp-syn-recv)
  (tcp-state-function
   (lambda () (cond ((inclusive-tcp-flag? FIN)
		     (tcp-abort))
		    ((and (inclusive-tcp-flag? ACK) (valid-acknum?))
		     (link-to-app)
		     (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
		     (pass-to-another-state tcp-established)
		     (tcp-transfers-controller 0 #t #t))))))


;; Tools for TCP state functions

;; some codes for the TCP flags
(define FIN 1)
(define SYN 2)
(define RST 4)
(define PSH 8)
(define ACK 16)
(define URG 32)


;; set the general connection state to ABORTED
;; which means the connection cannot be used anymore because of a protocol
;; error or a too long inactivity period.
(define (tcp-abort)
  (tcp-transfers-controller RST #f #f)
  (conn-info-set! curr-conn conn-state ABORTED) ;; TODO try to get rid of these states
  (detach-curr-conn))
;; close the connection, it has ended properly
(define (tcp-end)
  (pass-to-another-state (lambda () #f))
  (conn-info-set! curr-conn conn-state END)
  (detach-curr-conn))


(define (tcp-state-function phase2)
  (if (or (> (get-curr-elapsed-time) tcp-max-life-time) ; did the connection time out ?
	  ;; were there too many retransmission attempts for this packet
	  ;; already ?
          (> (conn-info-ref curr-conn tcp-attempts-count) tcp-attempts-limit)
          (= (conn-info-ref curr-conn conn-state) ABORTED)) ;; TODO if our peer closes or aborts, is the connection dropped from the list ? if so, it stays alive only as long as the application needs it
      (tcp-abort)
      (if (not (inclusive-tcp-flag? SYN)) ;; TODO do anything if it's a syn ?
	  (cond ((not (=conn-info-pkt? tcp-seqnum curr-conn
				       tcp-peer-seqnum 4))
		 ;; we have received data (the peer's seqnum is ahead), ACK it TODO is that really it ? make sure wih the standard, perhaps this means we received data that is too far ahead, and we should wait for what comes before ?
		 (tcp-transfers-controller ACK #f #f))
		((inclusive-tcp-flag? RST)
		 (tcp-abort))
		(else (phase2))))))


(define (pass-to-another-state new-state-function)
  (vector-set! curr-conn conn-state-function new-state-function)
  (conn-info-set! curr-conn tcp-attempts-count 0)
  (set-timestamp!)) ;; TODO now we have some repetition, all the 3 flags that were tested here and which called some functions, well, these functions are now called before this, all in the same way.


;; TODO this is disgusting, it's called with booleans and there's no way to see what's going on without jumping to the definition
;; TODO maybe use symbols to say what operations we will be making, keywords would be nice
(define (tcp-transfers-controller flags
				  receiver-on?
				  transmitter-on?)
  (u8vector-set! pkt tcp-flags flags)
  ;; input
  (let ((in-amount (- (pkt-ref-2 ip-length) 40))) ; 40 is the sum of the IP and TCP header lengths TODO have in a var, or make picobit optimize these arithmetic operations
    (if (and receiver-on?
	     (> in-amount 0))      
	(begin (set-timestamp!)
	       (if (<= in-amount ;; TODO was restructured, the original didn't care whether input succeeded or not and just acnowledged without checking
		       (buf-free-space (vector-ref curr-conn conn-input)))
		   (begin
		     ;; copy data to connection input buffer
		     (copy-u8vector->buffer! pkt
					     tcp-data
					     (vector-ref curr-conn conn-input)
					     in-amount)
		     (buf-inc-amount (vector-ref curr-conn conn-input)
				     in-amount) 
		     (increment-curr-conn-info! tcp-peer-seqnum 4 in-amount)
		     (turn-tcp-flag-on ACK))))))
  ;; output
  (let ((out-amount
	 (if (and (> (conn-info-ref curr-conn tcp-self-ack-units) 0)
		  (>= (get-curr-elapsed-time) tcp-retransmission-delay))
	     ;; a retransmission is needed
	     (conn-info-ref curr-conn tcp-self-ack-units)
	     (curr-buf-get-amount))))    
    (if (and transmitter-on?
	     (> out-amount 0))
	(begin
	  ;; copy data to connection output buffer
	  (copy-buffer->u8vector! (vector-ref curr-conn conn-output)
				  pkt
				  tcp-data
				  out-amount)
	  (increment-curr-conn-info! tcp-attempts-count 1 1)
	  (conn-info-set! curr-conn tcp-self-ack-units out-amount)
	  (turn-tcp-flag-on PSH)))
    (if (> (u8vector-ref pkt tcp-flags) 0) ;; TODO flags were passed, and maybe psh was set, so maybe we can tell without a ref
        (begin
          (if (> flags 0) (increment-curr-conn-info! tcp-attempts-count 1 1)) ;; TODO what ? understand the rationale behind this
          (set-timestamp!)
          (tcp-encapsulation out-amount)))))


;; to know if a particular tcp-flag is set
(define (inclusive-tcp-flag? tcp-flag)
  (= (modulo (quotient (get-tcp-flags) tcp-flag) 2) 1))

;; to know if only a particular tcp-flag is set
(define (exclusive-tcp-flag? flag)
  (= flag (get-tcp-flags)))

;; valid acknowledgement number ?
(define (valid-acknum?)
  (let ((new-acknum (u8vector-ref-field (vector-ref curr-conn 0)
					tcp-self-seqnum
					4)))
    (u8vector-increment! new-acknum 0 4 (conn-info-ref curr-conn tcp-self-ack-units))
    (u8vector-equal-field? pkt tcp-acknum new-acknum 0 4)))

(define (turn-tcp-flag-on flag)
  (u8vector-set! pkt tcp-flags (bitwise-ior flag (u8vector-ref pkt tcp-flags))))


(define (self-acknowledgement) ;; TODO what's that ? that's data that was sent but not acknowledged yet
  (let ((ack-units (conn-info-ref curr-conn tcp-self-ack-units)))
    (increment-curr-conn-info! tcp-self-seqnum 4 ack-units)
    (conn-info-set! curr-conn tcp-self-ack-units 0)
    (conn-info-set! curr-conn tcp-attempts-count 0)
    ack-units))


;; output
(define (tcp-encapsulation amount)
  (let ((len (+ tcp-header-length (if amount amount 0))))
    (integer->pkt 0 tcp-urgent-data-pointer 2)
    (integer->pkt 0 tcp-checksum 2)
    (integer->pkt (buf-free-space (vector-ref curr-conn conn-input))
		  tcp-window 2)
    ;; the header length (in bytes) converted to 32-bit words and shifted 4
    ;; bits to the left (4 reserved bits must be set to 0) which gives :
    ;; (* (quotient tcp-header-length 4) 16)
    (u8vector-set! pkt tcp-header-length-offset 80)
    (copy-curr-conn-info->pkt tcp-acknum tcp-peer-seqnum 4)
    (copy-curr-conn-info->pkt tcp-seqnum tcp-self-seqnum 4)
    (copy-curr-conn-info->pkt tcp-destination-portnum conn-peer-portnum 2)
    (integer->pkt (conf-ref curr-port conf-portnum) tcp-source-portnum 2)
    (ip-encapsulation
     (u8vector-ref-field (vector-ref curr-conn conn-info) conn-peer-ip 4)
     tcp-checksum
     compute-tcp-checksum
     len)))
