;;;; Vincent St-Amour
;;;; web-server.scm

;;;  simple web server, to be used as an example application for the stack
;;;  only handles GET, and only for a few static targets

(include "files-to-load.scm")

;; TODO change to use new API
(define connections '()) ;; the current connections being served by the server
;; we keep the input we received so far along with the connection, in case
;; it wasn't enough to decide how to react
;; therefore, each connection is a pair (conn . data), where conn is the
;; connection object we received from the stack, and data the data received
;; so far

(define targets ;; the different targets that can be GET
  (map (lambda (x)
	 (cons (car x)
	       (list->u8vector
		(map char->integer
		     (string->list
		      (string-append "HTTP/1.1 200 OK\r\n"
				     "\r\n<hmtl><body>"
				     (cdr x)
				     "</body></html>"))))))
       '(("foo" . "This is target foo.")
	 ("bar" . "This is target <b>bar</b>."))))
;; TODO we're not really http 1.1 compliant

(define (visit-all) ;; TODO use the code from the paper
  (let ((conn (car connections))))
  (if (visit conn)
      (cons conn (visit-all (cdr connections)))
      (begin (close-conn conn #t) ;; abort
	     (visit-all (cdr connections)))))

;; visit one connection, returns false when the connection is over
(define (visit conn)
  (let ((new-data (tcp-read (car conn))))
    (cond ((not new-data) #t) ;; we received nothing, we'll have to try again
	  ;; there's nothing, and we'll never get anything more, give up
	  ((equal? new-data 'end-of-input) #f)
	  ;; we have some new input, save it and try to answer the request
	  (else (set-cdr! conn
			  (string-append
			   (cdr conn)
			   (list->string (map integer->char
					      (u8vector->list new-data)))))
		(answer conn)))))

(define (answer conn)
  (let* ((data (cdr conn))
	 (len (string-length data))
	 (first-G (find-first #\G data 0 len))) ;; find the G of GET
    (cond
     ;; we didn't receive the GET yet
     ((or (not first-G) (>= (+ first-G 3) len)) #t)
     ;; invalid request, we drop the connection
     ((not (equal? (substring data first-G (+ first-G 4)) "GET ")) #f)
     ;; we did receive a GET, check the target
     ;; find the space at the end of the target
     (else (let* ((target-start (+ first-G 4))
		  (end-space (find-first #\space data target-start len)))
	     (cond
	      ;; we didn't receive the target yet
	      ((not end-space) #t)
	      ;; we have received the target, answer and close the connection
	      ;; we don't care about the rest of the request
	      (else
	       (serve-target (car conn)
			     (substring data target-start end-space))
	       (stack-task)
	       (close-conn (car conn))
	       #f))))))) ;; we won't need this connection in the list anymore

(define (find-first target data i len)
  (cond ((>= i len) #f)
	((equal? (string-ref data i) target) i)
	(else (find-first target data (+ i 1) len))))

;; send the target to the client
(define (serve-target conn target-name)
  (let ((target (assoc target-name targets)))
    (if target
	(tcp-write conn (cdr target))
	#f))) ;; the target doesn't exist, too bad

(define (tcp-filter dst-ip src-ip src-port)
  (equal? dst-ip my-ip))

(define (tcp-receive conn)
  (cons (cons conn "") connections))

(define (main-loop)
  (stack-task)
  (visit-all)
  (main-loop))

(tcp-bind 80 20 tcp-filter tcp-receive)

(main-loop)
