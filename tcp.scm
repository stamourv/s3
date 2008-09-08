;;;; Lysiane Bouchard - Vincent St-Amour
;;;; tcp.scm

;; TODO say what's really in here
;;;  - tcp state functions
;;;  - procedure called when a TCP packet is received:
;;;    see "tcp-pkt-in"


;; TODO what ?
(define tcp-opt-mss (u8vector 2 4 0 tcp-input-size 1 1 1 0))

;; specific manipulations of some subfields
(define (get-tcp-flags) (modulo (u8vector-ref pkt tcp-flags) 64))
(define (get-tcp-header-length) ;; TODO get rid of options support ?
  (* 4 (quotient (u8vector-ref pkt tcp-header-length) 16)))
;; we have to multiply by 4 since the header size is measured in words


;; called when a TCP packet is received
(define (tcp-pkt-in)
  (set! tcp-options-length (- (get-tcp-header-length) 20))
  (set! data-length (- (pkt-ref-2 ip-length) (get-tcp-header-length))) ;; TODO also remove ip header length ? would be the right thing, I guess
  (if (or (= (pkt-ref-2 tcp-checksum) 0) ; valid or no checksum ?
	  (valid-checksum? (compute-tcp-checksum)))
      (let ((port (search-port
		   (pkt-ref-2 tcp-destination-portnum)
		   tcp-ports)))
	(if (and port (pass-app-filter? tcp-source-portnum port))
	    ;; TODO use a not so the failure is closer to the condition ?
	    (begin (set! curr-port port)
		   ((make-transmission-to-conn tcp-source-portnum) tcp-listen))
	    (icmp-send-port-unreachable-error)))))


(define (compute-tcp-checksum)
  (pkt-checksum tcp-header
                (+ ip-header (pkt-ref-2 ip-length))
                (compute-tcp-pseudo-checksum))) ;; TODO is the pseudo needed ?
(define (compute-tcp-pseudo-checksum)
  (let ((tcp-length (- (pkt-ref-2 ip-length)
		       ip-header-length)))
    (pseudo-checksum (list (u8vector-ref pkt ip-protocol) ;; TODO use a u8vector-ref-field pkt, and then vector->list ?
                           tcp-length ;; TODO shouldn't we simply add this range to the real checksum ? maybe since then length is not there yet, it can cause problems
			   ;; TODO the first 2 are not 16 values, I think
                           (pkt-ref-2 ip-source-ip)
                           (pkt-ref-2 (+ ip-source-ip 2))
                           (pkt-ref-2 ip-destination-ip)
                           (pkt-ref-2 (+ ip-destination-ip 2)))
                     0)))


;;second tranmission : TODO inline this horror ? used only once in tcp-pkt-in
(define (make-transmission-to-conn src-portnum-idx)
  (lambda (P-listen) ;; TODO why return a lambda, I'm scared to find out, it's called right after it's created, always with tcp-listen as argument
    (let ((target-connection
	   (memp (lambda (c)
		   (and (=conn-info-pkt? src-portnum-idx c conn-peer-portnum 2)
			(=conn-info-pkt? ip-source-ip c conn-peer-ip 4)
			(=conn-info-pkt? ip-destination-ip c conn-self-ip 4)))
		 (get-curr-conns))))
      (if target-connection
	  (begin (set! curr-conn target-connection)
		 ((vector-ref target-connection conn-state-function)))
	  (P-listen)))))


;;-------TCP connections ----------------------------
;; TODO since only tcp has connections anymore, should we put conns (and ports) here, or put the next functions in conn ?
;; TODO put the next stuff in conn ?

;; to get the peer's segment's maximum size encoded in the packet
(define (get-peer-mss pkt-idx)
  (cond ((or (>= (- pkt-idx tcp-header)
                 (get-tcp-header-length))
             (= (u8vector-ref pkt pkt-idx) 0)) ; we reached the end of the option list
         (conn-info-set! curr-conn tcp-peer-mss tcp-output-size))
        ((= (u8vector-ref pkt pkt-idx) 1) ; we have a no-op in the tcp options
         (get-peer-mss (+ pkt-idx 1))) ; continue checking for mss
        ((= (u8vector-ref pkt pkt-idx) 2) ; we have found the mss
         (let ((mss (pkt-ref-2 (+ pkt-idx 2))))
           (if (> mss tcp-output-size)
               (conn-info-set! curr-conn tcp-peer-mss tcp-output-size)
               (conn-info-set! curr-conn tcp-peer-mss mss))))
        ;; keep looking after the current option
        (else (get-peer-mss (+ pkt-idx (u8vector-ref pkt (+ pkt-idx 1)))))))
;; TODO this might have been broken

;;----------tcp state functions --------------------------------------------


;; each one of those function garanties the behaviour of
;; the tcp protocol according to a specific standard tcp state.

;; tcp state time-wait
(define (tcp-time-wait)
  (let ((phase2 (lambda () #t))
        (inspection (lambda () (if (> (get-curr-elapsed-time)
                                      tcp-time-to-wait)
                                   (tcp-end)))))
    (tcp-state-function phase2 inspection)))

;; tcp state fin-wait-2
(define (tcp-fin-wait-2)
  (let ((phase2
         (lambda ()
           (if (inclusive-tcp-flag? FIN)
               (begin (pass-to-another-state tcp-time-wait #f #f #t)
                      (tcp-transferts-controller #f ACK #t #f))
               (tcp-transferts-controller #f 0 #t #f))))
        (inspection (make-closed-inspection 0)))
    (tcp-state-function phase2 inspection)))


;; tcp state closing
(define (tcp-closing)
  (let ((phase2
         (lambda ()
           (if (and (inclusive-tcp-flag? ACK)
                    (valid-acknum?))
               (begin (pass-to-another-state tcp-time-wait #f #t #f)
                      (tcp-transferts-controller #f ACK #f #f)))))
        (inspection
         (make-closed-inspection FIN)))
    (tcp-state-function phase2 inspection)))


;; tcp state fin-wait-1
(define (tcp-fin-wait-1)
  (let ((phase2
         (lambda ()
           (if (inclusive-tcp-flag? FIN)
               (begin
                 (if (and (inclusive-tcp-flag? ACK)
                          (valid-acknum?))
                     (pass-to-another-state tcp-time-wait #f #t #t)
                     (pass-to-another-state tcp-closing #f #f #t))
                 (tcp-transferts-controller #f ACK #t #f))
               (begin (if (and (inclusive-tcp-flag? ACK)
                               (valid-acknum?))
                          (pass-to-another-state tcp-fin-wait-2 #f #t #f))
                      (tcp-transferts-controller #f 0 #t #f)))))
        (inspection
         (make-closed-inspection  FIN)))
    (tcp-state-function phase2 inspection)))


                                        ;tcp state last-ack
(define (tcp-last-ack)
  (let ((phase2
         (lambda ()
           (if (and (inclusive-tcp-flag? ACK)
                    (valid-acknum?))
               (tcp-end))))
        (inspection  (make-closed-inspection FIN)))
    (tcp-state-function phase2 inspection)))


                                        ;tcp state close-wait
(define (tcp-close-wait)
  (let ((phase2 (lambda ()
                  (if (and (inclusive-tcp-flag? ACK) (valid-acknum?))
                      (self-acknowledgement))
                  (tcp-transferts-controller #f 0 #f #t)))
        (inspection (make-opened-inspection #f 0 #t tcp-last-ack #f #f)))
    (tcp-state-function phase2 inspection)))


                                        ;tcp state established
(define (tcp-established)
  (let ((phase2
         (lambda ()
           (if (and (inclusive-tcp-flag? ACK) (valid-acknum?))
	       ;; we have received an ACK, we can consume the data that was
	       ;; acknowledged
               (buf-consume (vector-ref curr-conn conn-output)
			    (self-acknowledgement)))
           (if (inclusive-tcp-flag? FIN)
               (begin (pass-to-another-state tcp-close-wait #f #t #t)
                      (tcp-transferts-controller #f ACK #t #t))
               (tcp-transferts-controller #f 0 #t #t))))
        (inspection (make-opened-inspection #f 0 #t tcp-fin-wait-1 #f #f)))
    (tcp-state-function phase2 inspection)))

                                        ;tcp state syn-received
(define (tcp-syn-recv)
  (let ((phase2
         (lambda ()
           (cond ((inclusive-tcp-flag? FIN)
                  (tcp-abort))
                 ((and (inclusive-tcp-flag? ACK) (valid-acknum?))
                  (link-to-app)
                  (pass-to-another-state tcp-established #f #t #f) ;; TODO yuck, no way to see what the flags for these 2 calls mean
                  (tcp-transferts-controller #f 0 #t #t)))))
        (inspection (make-opened-inspection tcp-opt-mss
                                            (+ SYN ACK)
                                            #f ;; TODO same here
                                            tcp-fin-wait-1
                                            #t
                                            #f)))
    (tcp-state-function phase2 inspection)))


					;tcp state listen
(define (tcp-listen)
  (if (and (< (length (get-curr-conns))
	      (conf-ref curr-port conf-max-conns))
           (exclusive-tcp-flag? SYN))
      (begin (new-conn)
             (pass-to-another-state tcp-syn-recv #t #f #t)
             (tcp-transferts-controller tcp-opt-mss (+ SYN ACK) #f #f))))


;; Tools for TCP state functions

;; some codes for the TCP flags
(define FIN 1)
(define SYN 2)
(define RST 4)
(define PSH 8)
(define ACK 16)
(define URG 32)


(define (tcp-abort)
  (tcp-transferts-controller #f RST #f #f)
  (abort))
(define (tcp-closed) #f)
(define (tcp-end)
  (pass-to-another-state tcp-closed #f #f #f)
  (end))


;; set the general connection state to ABORTED
;; which means the connection cannot be used anymore because of a protocol
;; error or a too long inactivity period.
(define (abort)
  (conn-info-set! curr-conn conn-state ABORTED)
  (detach-curr-conn))

;; set the general connection state to END
;; the connection cannot be used, but it has ended properly.
(define (end)
  (conn-info-set! curr-conn conn-state END)
  (detach-curr-conn))


(define (tcp-state-function tcp-reception-phase2 inspection)
  (if (or (conn-timed-out? tcp-max-life-time) ;; TODO only use
          (too-much-attempts?) ;; TODO only use
          (conn-aborted?)) ;; TODO only use
      (tcp-abort)
      (if (stack-lock-conn)
	  
	  (let ((out ;; TODO yuck
		 (if (not (inclusive-tcp-flag? SYN))
		     (cond ((not (valid-seqnum?))
			    (tcp-transferts-controller #f ACK #f #f)) ; TODO ok, so we send an ack saying what ? looks like we didn't get the data we were waiting for, why do we ack, shouldn't we simply discard it ?
			   ((inclusive-tcp-flag? RST)
			    (tcp-abort)) ; TODO clean up, was simply inlined
			   (else (tcp-reception-phase2))))))
	    (stack-release-conn)
	    out)  ;; TODO release here ? or does the connection have a change of not existing anymore ?
	  
	  (inspection)))) ;; TODO wtf, using the other lock caused a problem in the tests, but got rid of the incriminating lock changes, without being able to figure out why they were there in the first place


(define (conn-timed-out? max-life-time) ;; TODO used only once
  (> (get-curr-elapsed-time) max-life-time))


(define (make-opened-inspection options
                                flags
                                transmitter-on?
                                close-function
                                special-flag-to-ack?
                                peer-ack?)
  (lambda ()
    (if (and (conn-closed?)
             (not (output?))) ;; TODO why output? and not tcp-output? ?
        (begin (pass-to-another-state close-function
                                      #t
                                      special-flag-to-ack?
                                      peer-ack?)
               (tcp-transferts-controller #f FIN #f #f))
        (begin  (tcp-transferts-controller (if (retransmission-needed?)
                                               options
                                               #f)
                                           flags
                                           #f
                                           transmitter-on?)))))

                                        ;Is there data in the output buffer of the current connection?
(define (output?)
  (let ((amount (curr-buf-get-amount)))
    (if (> amount 0) amount #f)))

(define (make-closed-inspection flags)
  (lambda () (tcp-transferts-controller #f flags #f #f)))


(define (pass-to-another-state new-state-f
                               special-flag-to-send?
                               special-flag-to-ack?
                               peer-ack?)
  (vector-set! curr-conn conn-state-function new-state-f)
  (conn-info-set! curr-conn tcp-attempts-count 0)
  (if special-flag-to-ack? (self-acknowledgement))
  (if special-flag-to-send? (conn-info-set! curr-conn tcp-self-ack-units 1))
  (if peer-ack? (increment-curr-conn-info! tcp-peer-seqnum 4 1))
  (set-timestamp!))


(define (tcp-receiver) ;; TODO used only once
  (let ((in-amount
	 
	 ;; TODO inline simple-receiver ? or could it end up being used by udp?

	 (simple-receiver (+ ip-header-length (get-tcp-header-length)))))
    (if in-amount
        (begin (increment-curr-conn-info! tcp-peer-seqnum 4 in-amount)
               in-amount)
        #f)))

(define (input? headers-len) ;; TODO could this conceivably be used elsewhere ?
  ;; returns the amount of input data in the packet, or false if none
  (let ((in-amount (- (pkt-ref-2 ip-length) headers-len)))
    (if (> in-amount 0) in-amount #f))) ;; TODO used once (in the previous function) try to inline ? was originally an internal define of simple-receiver, which was inlined in tcp-receiver (actually, not yet inlined)

;if there is input and if there is enough place for it, stores it,
;otherwise, returns #f 
(define (simple-receiver headers-size) ;; TODO used only once, in the previous function, but maybe use it for tcp ?
  (let ((in-amount (input? headers-size)))
    (if in-amount 
	(begin (input-has-succeeded? in-amount tcp-data)
	       (set-timestamp!)
	       in-amount)
	#f)))

;Is there enough of free space in the input buffer? 
;Yes : we transmit input datas and return the number of bytes.
;No : returns #f
(define (input-has-succeeded? in-amount pkt-idx)
  (if (<= in-amount (buf-free-space (vector-ref curr-conn conn-input))) ;; TODO maybe put as much as we can and only ack that ? or would it be too complex ?
      (begin (copy-u8vector->buffer! pkt ; copy data to connection input buffer
				     pkt-idx
				     (vector-ref curr-conn conn-input)
				     in-amount)
	     (buf-inc-amount (vector-ref curr-conn conn-input) in-amount) 
	     in-amount)
      #f))


(define (tcp-transmitter)
  (let ((out-amount (tcp-output?))) ;; TODO only use of tcp-output?
    (if out-amount
        (begin
	  (copy-buffer->u8vector! (vector-ref curr-conn conn-output)
				  pkt ; copy data to connection output buffer
				  tcp-data
				  out-amount)
	  ;; TODO last line was in simple-transmitter, but since it was only used once, it ended up inlined, the clearing part was removed since it was always passed #f (actually the old udp did pass #t, but it's gone anyways)
          (increment-curr-conn-info! tcp-attempts-count 1 1)
          (conn-info-set! curr-conn tcp-self-ack-units out-amount)))
    out-amount))
;; TODO when do we get rid of output data if we received the ack ?

;; may not be used in states consuming special ack units
;; (SYN flag or FIN flag)
(define (tcp-output?) ;; TODO only used once, maybe inline ? actually, is passed as parameter to simple-transmitter, but is the only parameter ever
  (let ((data-length (output?)))
    (cond ((retransmission-needed?)
	   (conn-info-ref curr-conn tcp-self-ack-units))
          (data-length
	   (min data-length (conn-info-ref curr-conn tcp-peer-mss)))
          (else #f))))


(define (tcp-transferts-controller options ;; TODO this is disgusting, it's called with booleans and there's no way to see what's going on without jumping to the definition
                                   flags
                                   receiver-on?
                                   transmitter-on? )
  (u8vector-set! pkt tcp-flags flags)
  (if (and receiver-on? (tcp-receiver)) (turn-tcp-flag-on ACK))
  (set! tcp-options-length (if options (u8vector-length options) 0))
  (u8vector-copy! options 0 pkt tcp-options tcp-options-length) ; set options
  (let ((out-amount (if transmitter-on? (tcp-transmitter) 0)))
    (if (> (if out-amount out-amount 0) 0) ;; TODO ugly, but tcp-transmitter can give #f
	(turn-tcp-flag-on PSH))
    (if (> (u8vector-ref pkt tcp-flags) 0)
        (begin
          (if (> flags 0) (increment-curr-conn-info! tcp-attempts-count 1 1))
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
    ;; TODO find out what these self-ack-units are
    (u8vector-equal-field? pkt tcp-acknum new-acknum 0 4)))

(define (turn-tcp-flag-on flag)
  (u8vector-set! pkt tcp-flags (bitwise-ior flag (u8vector-ref pkt tcp-flags))))


;; TODO reorganise the order of all these functions, it's a mess
;too much transmissions of the same packet ?
(define (too-much-attempts?)
  (> (conn-info-ref curr-conn tcp-attempts-count) tcp-attempts-limit))

(define (retransmission-needed?)
  (and (> (conn-info-ref curr-conn tcp-self-ack-units) 0) ; TODO ok, looks like the self-ack stuff is the number of bytes we have sent that were not confirmed yet by the receiver
       (>= (get-curr-elapsed-time) tcp-retransmission-delay)))


;Assume there is input data. Is the sequence number valid?
(define (valid-seqnum?)
  (=conn-info-pkt? tcp-seqnum curr-conn tcp-peer-seqnum 4)) ;; TODO inline ?


(define (conn-closed?)
  (= (conn-info-ref curr-conn conn-state) CLOSED))

(define (conn-aborted?)
  (= (conn-info-ref curr-conn conn-state) ABORTED))
;; TODO if our peer closes or aborts, is the connection dropped from the list ? if so, it stays alive only as long as the application needs it


(define (self-acknowledgement) ;; TODO what's that ? would is be related to selective acknowledgement ?
  (let ((ack-units (conn-info-ref curr-conn tcp-self-ack-units)))
    (increment-curr-conn-info! tcp-self-seqnum 4 ack-units)
    (conn-info-set! curr-conn tcp-self-ack-units 0)
    (conn-info-set! curr-conn tcp-attempts-count 0)
    ack-units))


;; output
(define (tcp-encapsulation amount)
  (let ((len (+ 20 tcp-options-length (if amount amount 0))))
    (integer->pkt 0 tcp-urgent-data-pointer 2)
    (integer->pkt 0 tcp-checksum 2)
    (integer->pkt (buf-free-space (vector-ref curr-conn conn-input)) tcp-window 2)
    (u8vector-set! pkt ; set the header length
		   tcp-header-length
		   ;; the length (in bytes) converted to 32-bit words and
		   ;; shifted 4 bits to the left
		   ;; which gives : (* (quotient header-length 4) 16)
		   (* (+ tcp-options-length 20) 4)) ;; TODO if we get rid of options, have static
    (copy-curr-conn-info->pkt tcp-acknum tcp-peer-seqnum 4)
    (copy-curr-conn-info->pkt tcp-seqnum tcp-self-seqnum 4)
    (copy-curr-conn-info->pkt tcp-destination-portnum conn-peer-portnum 2)
    (integer->pkt (conf-ref curr-port conf-portnum) tcp-source-portnum 2)
    (ip-encapsulation
     (u8vector-ref-field (vector-ref curr-conn 0) conn-peer-ip 4)
     tcp-checksum
     compute-tcp-checksum
     len)))
