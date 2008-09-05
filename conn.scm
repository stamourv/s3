;;;; Lysiane Bouchard - Vincent St-Amour
;;;; conn.scm

;; TODO what really is in there
;;;  - connection structure and related operations
;;;  - operations on the current connection
;;;  - external operations on a connection

;;; Note : connections are used only with tcp
;; TODO merge all this with tcp ? it's only used with tcp. would result in a huge file, though

;; connection structures are represented as vectors :
;; FORMAT: 5 fields:
;; -0: informations (u8vector)
;;     contains:
;;     - which of the stack's IP addresses uses the connection
;;     - peer's IP address
;;     - peer's source port number
;;     - peer's MAC address
;;     - connection state TODO useful ?
;;     - the acknoledgement number at which the stack is for this connection
;;     - number of self-ack units TODO what's that ?
;;     - the acknoledgement number at which our peer is
;;     - number of attemps so far TODO make sure it's so far
;;     - peer's Maximum Size Segment (MSS)
;;     Note : storing our port number in the connection structure is unecessary
;; -1: timestamp (integer) TODO which unit ?
;; -2: input buffer (u8vector)
;; -3: output buffer (u8vector)
;; -4: state function (function)
;;     defines the connection's behaviour at a given time.
;; -5: lock
;;      a simple mutex (with Peterson's algorithm) that makes sure that the
;;      application does not access its data while the stack is modifying it
;; TODO add retries for the stack if the application holds a connection, or simply drop the packet ? can't happen in a single threaded application


;; informations
(define conn-self-IP       0)
(define conn-peer-IP       4) ;; TODO see if it's necessary or if a simple swap can do the job
(define conn-peer-portnum  8) ;; TODO same here
(define conn-peer-MAC      10) ;; TODO same here
(define conn-state         16) ;; TODO useful ? if not, remove and shift all the others
(define tcp-self-seqnum    17) ;; TODO were calculated, but these were the only infos after state anyway
(define tcp-self-ack-units 21) ;; TODO what's that ?
(define tcp-peer-seqnum    22) ;; TODO add conn- before ?
(define tcp-attempts-count 26)
(define tcp-peer-mss       27)
(define tcp-infos-size     28)


;; connection state
(define ACTIVE  0) ;; TODO how is this used ? don't state functions take care of this ? see if we can drop
(define CLOSED  1)
(define ABORTED 2)
(define END     3)


;; general operations
(define (conn-info-ref conn i) (u8vector-ref (vector-ref conn 0) i))
(define (conn-info-set! conn i val) (u8vector-set! (vector-ref conn 0) i val))
(define (set-timestamp! conn) (vector-set! conn  1 (get-current-time)))
(define (set-curr-timestamp!) (set-timestamp! curr-conn))
(define (get-curr-elapsed-time) (get-elapsed-time (vector-ref curr-conn 1)))
(define (get-input conn) (vector-ref conn 2)) ;; TODO use something like conn-info-ref and offsets ? actually, the only input got is from current connection, so maybe have that instead, NOT the same case for output, which uses on one occasion a generic connection, which cannot be guaranteed to be the current one
(define (get-output conn) (vector-ref conn 3))
(define (get-state-function conn) (vector-ref conn 4)) ;; TODO both get and set are used once, some kind of offset system might be a better idea, but not sure
(define (set-state-function conn sf) (vector-set! conn 4 sf))

;; a lock is represented as a vector, 1st element is #t if the stack wants to
;; access the connection, the 2nd is #t if the application wants to, the 3rd
;; is #t if the priority is to the application (see Peterson's algorithm)
(define (stack-lock-conn)
  ;; the stack can only lock and unlock the current connection
  (let ((lock ((vector-ref curr-conn 5))))
    (vector-set! lock 0 #t)
    (vector-set! lock 2 #t)
    (if (and (vector-ref lock 1) (vector-ref lock 2))
	;; we can't lock the connection
	(begin (vector-set! lock 0 #f) (vector-set! lock 2 #t) #f)
	#t)))
;; returns #f if we can't lock, so we can drop the packet instead of waiting
(define (stack-release-conn) (vector-set! (vector-ref curr-conn 5) 0 #f))
(define (app-lock-conn conn)
  (let ((lock (vector-ref conn 5)))
    (vector-set! lock 1 #t)
    (vector-set! lock 2 #f)
    (if (and (vector-ref lock 0) (not (vector-ref lock 2)))
	;; we can't lock the connection
	(begin (vector-set! lock 1 #f) (vector-set! lock 2 #f) #f)
	#t)))
(define (app-release-conn conn) (vector-set! (vector-ref conn 5) 1 #f))


;; comparison with packet data TODO put with other functions ?
(define (=conn-info-pkt? pkt-idx c c-idx n)
  (=subfield-pkt-n? pkt-idx (vector-ref c 0) c-idx n))


;; creates a new connection with the info in the incoming packet
;; it becomes the current connection
(define (new-conn)
  ;; TODO clean this up a bit, are some operations redundant ? are all necessary ?
  (let ((c (vector (make-u8vector tcp-infos-size 0)
                   #f
                   (make-u8vector (+ tcp-input-size 2) 0)
                   (make-u8vector (+ tcp-output-size 2) 0)
                   tcp-syn-recv
		   (vector #f #f #f))))
    (add-conn-to-curr-port c)
    (copy-pkt->curr-conn-info ip-dst-IP conn-self-IP 4) ;; TODO useful ?
    (copy-pkt->curr-conn-info tcp-src-portnum conn-peer-portnum 2)
    (copy-pkt->curr-conn-info ip-src-IP conn-peer-IP 4) ;; TODO why these 2 ? we can probably just swap when we create the response, no ?
    (copy-pkt->curr-conn-info eth-src-MAC conn-peer-MAC 6) ;; TODO do we need this ? we can simply answer to the sender
    (set-timestamp! c)
    (copy-u8->pkt-4 tcp-self-seqnum (tcp-isn))
    (copy-pkt->curr-conn-info tcp-seqnum tcp-peer-seqnum 4)
    (get-peer-mss tcp-options)
    (set! curr-conn c)))


;; an input/output buffers is a byte vector of length n + 2 with n being the
;; buffer size chosen in conf.scm
;; the first 2 bytes contain the amount of data stored in the buffer and the
;; index of the next free space (with 0 being the first byte after the header),
;; in that order
(define buf-amount 0)
(define buf-pointer 1)
(define buf-header-size 2) ;; TODO all uses in this file
;; TODO get rid of these, not used, but put doc comments instead
;; TODO say somehwere that the max is 256, probably in conf.scm
;; TODO is it a good idea to store these infos in the vector proper ? the code is more complex CHANGE IT

;; returns the number of actual data bytes that can be stored in the buffer
(define (buf-size buf)
  (- (u8vector-length buf) buf-header-size))
;; TODO get rid if we put pointer and amount outside

(define (curr-buf-get-amount) (u8vector-ref (get-output curr-conn) buf-amount))
;; TODO only used once, and in a debatable way
(define (buf-inc-amount buf n) ;; TODO not really inc/dec since it's not 1 but n
  (u8vector-set! buf buf-amount (+ (u8vector-ref buf buf-amount) n)))
(define (buf-dec-amount buf n)
  (u8vector-set! buf buf-amount (- (u8vector-ref buf buf-amount) n)))
(define (buf-inc-pointer buf n)
  (u8vector-set! buf
                 buf-pointer
                 (modulo (+ (u8vector-ref buf buf-pointer) n)
                         (buf-size buf))))

(define (buf-free-space buf) ;; TODO this might be used for redundant checks
  (- (u8vector-length buf) (u8vector-ref buf buf-amount) buf-header-size))


;; clears the first n bytes of data in the buffer
;; or the whole buffer if there is less than n bytes
;; of data inside
;; TODO change name, it's actually more of a data consumption rather than a clear, we don't erase anything
(define (buf-clear-n buf n)
  (if (>= n (u8vector-ref buf buf-amount))
      (begin (u8vector-set! buf buf-amount 0)
             (u8vector-set! buf buf-pointer 0))
      (begin (buf-dec-amount buf n)
             (buf-inc-pointer buf n))))


(define (copy-pkt->curr-conn-info pkt-idx conn-idx n) ;; TODO standardise name
  (copy-pkt->subfield-n pkt-idx (vector-ref curr-conn 0) conn-idx n))
(define (copy-curr-conn-info->pkt pkt-idx conn-idx n) ;; TODO standardise name
  (copy-subfield->pkt-n (vector-ref curr-conn 0) conn-idx pkt-idx n))

;; data transfers from the packet to the input buffer of the current
;; connection. No verification of input room TODO rendu ici
(define (copy-pkt->curr-input-n pkt-idx n)
  (copy-u8vector->buffer! pkt pkt-idx (get-input curr-conn) n))

;; data transfers from the current output buffer to the packet
;; no verification of output amount
(define (copy-curr-output->pkt-n pkt-idx n)
  (copy-buffer->u8vector! (get-output curr-conn) pkt pkt-idx n))


;; TODO we're still doomed if offset if more than 24 bits
;; add offset to the field of n bytes that begins at idx
;; TODO is this used often enough to be worth it ?
(define (increment-curr-conn-n idx offset n) ;; TODO weird argument order, and should have a !, since it is destructive
  (u8vector-increment-n! (vector-ref curr-conn 0) idx n offset))
;; TODO see if the custom setter (the one that sets the informations inside the connection) is still used, since we kind of circumvent it here (to avoid having to send a setter instead of a vector, which is ugly)

;; Links the current connection with the corresponding application
;; sends the connection to the application, which can then access it at
;; any time
(define (link-to-app) ((conf-ref curr-port conf-reception) curr-conn)) ;; TODO used only once, in tcp INLINE


;; detach the current connection from the current port
(define (detach-curr-conn) ;; TODO put with ports ?
  (detach-curr-conn-loop curr-port))
(define (detach-curr-conn-loop lst) ;; TODO have a ! in the name
  (if (pair? (cdr lst)) ;; TODO have an accessor for conf and conns ? but this is not really a conn
      (if (eq? (cadr lst) curr-conn)
	  (set-cdr! lst (cddr lst))
	  (detach-curr-conn-loop (cdr lst)))))


;; copy n bytes from a circular buffer to a byte vector
;; this consumes the data from the buffer, it cannot be read again
;; we are guaranteed that n cannot be greater than the number of bytes that can
;; actually be read
(define (copy-buffer->u8vector! buf vec i-vec n)
  ;; the copy starts at the current location in the buffer
  (let ((i-buf (u8vector-ref buf buf-pointer))
	(size (buf-size buf)))
    (if (<= (+ i-buf n) size) ; wraparound
	(let ((n1 (- size i-buf 1))) ;; TODO watch out for off-by-one
	  (u8vector-copy! buf i-buf vec i-vec n1)
	  (u8vector-copy! buf buf-header-size vec (+ i-vec n1) (- n n1)))
	(u8vector-copy! buf i-buf vec i-vec n))
    (buf-dec-amount buf n)
    (buf-inc-pointer buf n)))

;; TODO does this obsolete other functions ?
;; copy n bytes of data from a vector to a circular buffer
;; once again, we are guaranteed that the copy is valid, that the buffer has
;; enough room for the new data
;; TODO a lot in common with the previous, find a way to merge ?
;; returns the offset of the next empty space in the buffer.
;; if the buffer is full, returns #f
(define (buf-next-free-space buf)
  (let ((n (- (u8vector-length buf) buf-header-size))
        (amount (u8vector-ref buf buf-amount)))
    (if (< amount n) amount #f))) ;; TODO inline
(define (copy-u8vector->buffer! vec i-vec buf n)
  (let ((data-size (buf-size buf))
	(amount (u8vector-ref buf buf-amount))
	(i-buf (buf-next-free-space buf)) ;; TODO err, actually, shouldn't it be pointer ?
	(size (buf-size buf)))
    (if i-buf ;; TODO since the check is made upstream, we should always have enough space
	(begin
	  (if (<= (+ i-buf n) size) ; wraparound
	      (let ((n1 (- size i-buf 1))) ;; TODO off-by-one ?
		(u8vector-copy! vec i-vec buf i-buf n1)
		(u8vector-copy! vec (+ i-vec n1) buf buf-header-size (- n n1)))
	      (u8vector-copy! vec i-vec buf i-buf n))
	  (buf-inc-amount buf n))
	#f)))

;; Exterior manipulations on a connection
;; If a process exterior to the stack asks to manipulate a connection,
;; some verification has to be done before agreeing.
;; Some data structures are shared and cannot be used at the same time
;; by two different processes.
;; For example, an application cannot send data if the stack is receiving a
;; new packet because there is only one packet in the system at a time.

;; read n input bytes from the connection c, if n is omitted, read all
;; TODO the changes were not tested
(define (tcp-read c . n) ;; TODO quite ugly
  (if (and (app-lock-conn c)
           (<= (conn-info-ref c conn-state) CLOSED)) ;; active or closed
      (let* ((buf (get-input c))
	     (available (u8vector-ref buf buf-amount))
	     (amount (if (null? n)
			 available
			 (min available (car n))))
	     (out (cond ((> amount 0)
			 (let ((data (make-u8vector amount 0)) (i 0))
			   (copy-buffer->u8vector! buf data 0 amount)
			   data))
			((= (conn-info-ref c conn-state) CLOSED) 'end-of-input) ;; TODO better end marker ? and do we really need this ? we can't really know if this is really the end of the data, maybe check both if we have no data left and the connection is closed, also we check the state twice, cache ?
			(else #f))))
	(app-release-conn c)
	out)
      #f))

;; write bytes (in a u8vector) to c, returns the number of bytes written
(define (tcp-write c data)
  (if (and (app-lock-conn c)
           (= (conn-info-ref c conn-state) ACTIVE))
      (let* ((buf (get-output c))
	     (amount (min (buf-free-space buf) (u8vector-length data)))
	     (out (if (> amount 0)
		      (begin
			(copy-u8vector->buffer! data 0 buf amount)
			amount)
		      #f))) ;; TODO distinguish from the #f from a failed lock, or do we really need to ? since in both cases, we'd have to retry the write (except if the connection is closed, how to know ?)
	(app-release-conn c)
	out)
      #f))


;; API function to terminate a connection
(define (tcp-close conn . abort?) (if abort? (abort-conn c) (close-conn c)))

                                        ;ask the protocol to close the connection
                                        ;(set the "conn-state" subfield to "CLOSED")
(define (close-conn c)
  (if (and (app-lock-conn c)
           (= (conn-info-ref c conn-state) ACTIVE))
      (begin (conn-info-set! c conn-state CLOSED)
	     (app-release-conn c)
	     #t)
      #f)) ;; TODO do we tell our peer that we closed ? if so, when, do we wait for him to send us a packet and we respond with that ? we'll have to check this, also, when is it dropped from the port structure ?


                                        ;ask the protocol to abort the connection
                                        ;(set the "conn-state" subfield to "ABORT")
(define (abort-conn c)
  (if (and (app-lock-conn c)
           (<= (conn-info-ref c conn-state) CLOSED))
      (begin (conn-info-set! c conn-state ABORTED) (app-release-conn c) #t)
      #f))

                                        ;get the general state of the connection : ACTIVE/CLOSED/ABORTED/END
(define (get-conn-state c)
  (if (app-lock-conn c) ;; TODO do we really need to lock for that ?
      (let ((out (conn-info-ref c conn-state)))
	(app-release-conn c)
	out)
      #f))
