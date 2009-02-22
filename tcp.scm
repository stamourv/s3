;;;; Lysiane Bouchard - Vincent St-Amour
;;;; tcp.scm

;; TODO say what's really in here
;;;  - tcp state functions
;;;  - procedure called when a TCP packet is received:
;;;    see "tcp-pkt-in"


;; specific manipulations of some subfields
(define (get-tcp-flags) (modulo (u8vector-ref pkt tcp-flags) 64)) ;; TODO inline ?

;; called when a TCP packet is received
(define (tcp-pkt-in)
  ;; 40 is the sum of the sizesof the IP and TCP headers
  (cond ((not (= (u8vector-ref pkt tcp-header-length-offset) 80)) ;; TODO have this 80 in a variable ?
	 ;; the packet has TCP options (header longer than 20 bytes), we reject
	 ;; it. since the length is then always 20 bytes, followed by 4 reserved
	 ;; bits (which must be set to 0), we simply must check if the byte is
	 ;; equal to (20 / 4) << 4 = 80
	 #f))
  (if (or (= (pkt-ref-2 tcp-checksum) 0) ; valid or no checksum ?
	  (= 65535 (compute-tcp-checksum)))
      (let ((port (search-port (pkt-ref-2 tcp-destination-portnum)
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
			   ;; call the current state function
			   ((vector-ref target-connection conn-state-function)))
		    ;; no matching connection was found, if we have not yet
		    ;; reached the maximum number of connections, establish a
		    ;; new one
		    (if (and (< (length (get-curr-conns)) ; TODO do something if false ? 
				(conf-ref curr-port conf-max-conns))
			     ;; the handshake must begin with a SYN
			     (exclusive-tcp-flag? SYN))
			(begin (new-conn) ; this sets the new connection as the current one
			       (self-acknowledgement) ;; TODO was in the call to transferts controller, but does it make any sense ?
			       (increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
			       (pass-to-another-state tcp-syn-recv)
			       (tcp-transfers-controller (+ SYN ACK) 0))))))
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
(define (tcp-fin-wait-2) ;; TODO most of the thunks sent to tcp-state-function are a test (usually for a flag, maybe more) and 1-2 thunks, maybe there is a way to optimize ? however, sometimes, there are actions after the if, or more than one if
  (tcp-state-function
   (lambda ()
     (tcp-receive-data)
     (if (inclusive-tcp-flag? FIN)
	 (begin (increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
		(pass-to-another-state tcp-time-wait)		
		(tcp-transfers-controller ACK 0))
	 (tcp-transfers-controller 0 0)))))


;; tcp state closing
(define (tcp-closing)
  (tcp-state-function
   (lambda () (if (and (inclusive-tcp-flag? ACK)
		       (valid-acknum?))
		  (begin (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
			 (pass-to-another-state tcp-time-wait)
			 (tcp-transfers-controller ACK 0))))))


;; tcp state fin-wait-1
(define (tcp-fin-wait-1)
  (tcp-state-function
   (lambda ()
     (tcp-receive-data)
     (if (inclusive-tcp-flag? FIN)
	 (begin
	   (if (and (inclusive-tcp-flag? ACK)
		    (valid-acknum?))
	       (begin (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
		      (increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
		      (pass-to-another-state tcp-time-wait))
	       (begin (increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
		      (pass-to-another-state tcp-closing)))
	   (tcp-transfers-controller ACK 0)) ;; TODO make sure this does what we want
	 (begin (if (and (inclusive-tcp-flag? ACK)
			 (valid-acknum?))
		    (begin (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
			   (pass-to-another-state tcp-fin-wait-2)))
		(tcp-transfers-controller 0 0))))))


;; tcp state last-ack
(define (tcp-last-ack)
  (tcp-state-function
   (lambda () (if (and (inclusive-tcp-flag? ACK)
		       (valid-acknum?))
		  (detach-curr-conn)))))


;; tcp state close-wait
(define (tcp-close-wait)
  (tcp-state-function
   (lambda ()
     (if (and (inclusive-tcp-flag? ACK) (valid-acknum?))
	 (self-acknowledgement))
     (tcp-send-data 0))))


;; tcp state established
(define (tcp-established)
  (tcp-state-function
   (lambda ()
     (if (and (inclusive-tcp-flag? ACK) (valid-acknum?))
	 ;; we have received an ACK, we can consume the data that was
	 ;; acknowledged
	 (buf-consume (vector-ref curr-conn conn-output)
		      (self-acknowledgement)))
     (tcp-receive-data)
     (if (inclusive-tcp-flag? FIN)
	 (begin (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
		(increment-curr-conn-info! tcp-peer-seqnum 4 1) ;; TODO 1, really ?
		(pass-to-another-state tcp-close-wait)
		(tcp-send-data ACK))
	 (tcp-send-data 0)))))

;; tcp state syn-received
(define (tcp-syn-recv)
  (tcp-state-function
   (lambda () (cond ((inclusive-tcp-flag? FIN)
		     (tcp-abort))
		    ((and (inclusive-tcp-flag? ACK) (valid-acknum?))
		     (link-to-app)
		     (conn-info-set! curr-conn tcp-self-ack-units 1) ;; TODO 1, really ?
		     (pass-to-another-state tcp-established)
		     (tcp-receive-data)
		     (tcp-send-data 0))))))


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
  (tcp-transfers-controller RST)
  (detach-curr-conn)) ;; TODO abstract that last call ?

(define (tcp-state-function phase2)
  (if (or (> (get-curr-elapsed-time) tcp-max-life-time) ; did the connection time out ?
	  ;; were there too many retransmission attempts for this packet
	  ;; already ?
          (> (conn-info-ref curr-conn tcp-attempts-count) tcp-attempts-limit))
      (tcp-abort)
      (if (not (inclusive-tcp-flag? SYN)) ;; TODO do anything if it's a syn ?
	  (cond ((not (=conn-info-pkt? tcp-seqnum curr-conn
				       tcp-peer-seqnum 4))
		 ;; we have received data (the peer's seqnum is ahead), ACK it TODO is that really it ? make sure wih the standard, perhaps this means we received data that is too far ahead, and we should wait for what comes before ?
		 (tcp-transfers-controller ACK))
		((inclusive-tcp-flag? RST)
		 (tcp-abort))
		(else (phase2))))))


(define (pass-to-another-state new-state-function)
  (vector-set! curr-conn conn-state-function new-state-function)
  (conn-info-set! curr-conn tcp-attempts-count 0)
  (set-timestamp!)) ;; TODO now we have some repetition, all the 3 flags that were tested here and which called some functions, well, these functions are now called before this, all in the same way.


(define (tcp-receive-data)
  (let ((in-amount (- (pkt-ref-2 ip-length) 40))) ; 40 is the sum of the IP and TCP header lengths TODO have in a var, or make picobit optimize these arithmetic operations
    (if (> in-amount 0)
	(begin (set-timestamp!)
	       (if (<= in-amount ;; TODO was restructured, the original didn't care whether input succeeded or not and just acnowledged without checking
		       (buf-free-space (vector-ref curr-conn conn-input)))
		   (begin
		     ;; copy data to connection input buffer
		     (copy-u8vector->buffer! pkt
					     tcp-data
					     (vector-ref curr-conn conn-input)
					     in-amount)
		     (buf-inc-amount (vector-ref curr-conn conn-input) ;; TODO cache the buffer
				     in-amount)
		     (increment-curr-conn-info! tcp-peer-seqnum 4 in-amount)
		     (turn-tcp-flag-on ACK)))))))

(define (tcp-send-data flags)
  (let ((out-amount
	 (if (and (> (conn-info-ref curr-conn tcp-self-ack-units) 0)
		  (>= (get-curr-elapsed-time) tcp-retransmission-delay))
	     ;; a retransmission is needed
	     (conn-info-ref curr-conn tcp-self-ack-units)
	     (curr-buf-get-amount))))
    (if (> out-amount 0)
	(begin
	  ;; copy data to connection output buffer
	  (copy-buffer->u8vector! (vector-ref curr-conn conn-output)
				  pkt
				  tcp-data
				  out-amount)
	  (increment-curr-conn-info! tcp-attempts-count 1 1)
	  (conn-info-set! curr-conn tcp-self-ack-units out-amount)
	  (turn-tcp-flag-on PSH)))
    (tcp-transfers-controller flags out-amount)))

;; TODO this is disgusting, it's called with booleans and there's no way to see what's going on without jumping to the definition
;; TODO maybe use symbols to say what operations we will be making, keywords would be nice
(define (tcp-transfers-controller flags output-length) ;; TODO rethink this part, I doubt this really needs to be this way
  (u8vector-set! pkt tcp-flags flags)
  (if (> (u8vector-ref pkt tcp-flags) 0) ;; TODO flags were passed, and maybe psh was set, so maybe we can tell without a ref
      (begin
	(if (> flags 0) (increment-curr-conn-info! tcp-attempts-count 1 1)) ;; TODO what ? understand the rationale behind this
	(set-timestamp!)
	(tcp-encapsulation output-length))))


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


(define (self-acknowledgement) ;; TODO that's data that was sent but not acknowledged yet
  (let ((ack-units (conn-info-ref curr-conn tcp-self-ack-units)))
    (increment-curr-conn-info! tcp-self-seqnum 4 ack-units)
    (conn-info-set! curr-conn tcp-self-ack-units 0)
    (conn-info-set! curr-conn tcp-attempts-count 0)
    ack-units))


;; output
(define (tcp-encapsulation output-length)
  (let ((len (+ tcp-header-length output-length)))
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
