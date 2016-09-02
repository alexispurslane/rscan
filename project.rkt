#lang rackjure
(require sha net/url
         net/http-client json
         sugar net/uri-codec)

(define (read-files-sha256 paths)
  (list paths
        (string-join (map (λ (path)
                            (with-input-from-file path
                              (λ ()
                                (~> path file-size read-bytes sha256 bytes->hex-string))))
                          paths) ",")))

(define (chunk n lst) (break-at lst (range 0 (length lst) n)))

(define (read-directory-sha256 dir)
  (define fs/ds (map #λ(build-path dir (path->string %)) (directory-list dir)))
  (map read-files-sha256 (chunk 25 (filter file-exists? fs/ds))))

(define (virustotal-test names sha)
  (define API-KEY "6af4e84e123608ef1bb2ffd2cda4dba822c20cf730afb7248efefd300ac8259e")
  (define-values (status-code header inport)
    (http-sendrecv
     "www.virustotal.com"
     "/vtapi/v2/file/report"
     #:method "POST"
     #:data (alist->form-urlencoded
             (list (cons 'apikey API-KEY)
                   (cons 'resource sha)))))
  (list names (read-json inport)))

(define (format-hash h [c "\033[0m"])
  (string-join (map #λ(string-append "\033[0m" %1 ": " %2 c) (hash-keys h) (hash-values h)) "\n"))

(define (draw-box inner-text)
  (define (remove-colors s)
    (~> s (string-replace "\033[91m" "")
        (string-replace "\033[92m" "")
        (string-replace "\033[1m" "")
        (string-replace "\033[0m" "")))
  (define lst (string-split inner-text "\n"))
  (define wall-len (+ 2 (apply max (map (compose string-length remove-colors) lst))))
  (define wall+text (map (lambda (x)
                           (let* ([diff (- wall-len (string-length
                                                     (remove-colors x)) 1)]
                                  [spcs (make-string diff #\space)])
                             (string-append "│ " x spcs "│"))) lst))
  (displayln (string-append "┌" (make-string wall-len (first (string->list "─"))) "┐"))
  (for-each displayln wall+text)
  (displayln (string-append "└" (make-string wall-len (first (string->list "─"))) "┘")))

(define (byte-format n)
  (define (fnum n) (~r n #:precision 2))
  (cond [(> n (expt 1024 6)) (format "~a EB" (fnum (/ n (expt 1024 6))))]
        [(> n (expt 1024 5)) (format "~a PB" (fnum (/ n (expt 1024 5))))]
        [(> n (expt 1024 4)) (format "~a TB" (fnum (/ n (expt 1024 4))))]
        [(> n (expt 1024 3)) (format "~a GB" (fnum (/ n (expt 1024 3))))]
        [(> n (expt 1024 2)) (format "~a MB" (fnum (/ n (expt 1024 2))))]
        [(> n 1024) (format "~a KB" (fnum (/ n 1024)))]
        [else (format "~a B" n)]))

(define (gen-positives p t) (format "Positives: ~a% (~a/~a)"
                                    (ceiling (* 100 (/ p t))) p t))
(define (basic-attrs name verdict) (hash "Date Scanned" (hash-ref verdict 'scan_date)
                                         "Filename" (path->string name)
                                         "Size" (byte-format (file-size name))
                                         "Resource" (hash-ref verdict 'resource)))

(define (display-verbose-verdict name verdict)
  (define attrs (basic-attrs name verdict))
  (define p (hash-ref verdict 'positives))
  (define t (hash-ref verdict 'total))
  (define positives (gen-positives p t))
  (displayln (string-append (format-hash attrs) "\n"))
  (for ([vtn (hash-keys (hash-ref verdict 'scans))]
        [vt (hash-values (hash-ref verdict 'scans))])
    (define color (if (hash-ref vt 'detected) "\033[91m" "\033[92m"))
    (display color)
    (draw-box (format "\033[0mVirus Scanner: ~a (v~a)~a\n\033[0m└ Verdict: \033[1m~a\033[0m~a"
                      vtn (hash-ref vt 'version) color (hash-ref vt 'result) color))
    (display "\033[0m"))
  (define color (if (> p 0) "\033[91m" "\033[92m"))
  (displayln (format "~a\033[1m~a\033[0m" color positives)))

(define (display-file-verdict name verdict [verbose? #t])
  (when (= (hash-ref verdict 'response_code) 1)
    (if verbose?
        (display-verbose-verdict name verdict)
        (let* ([attrs (basic-attrs name verdict)]
               [p (hash-ref verdict 'positives)]
               [t (hash-ref verdict 'total)]
               [positives (gen-positives p t)]
               [mash-hash (λ (h) (map #λ(hash-set %2 'name %1)
                                      (hash-keys h)
                                      (hash-values h)))]
               [results (sort (filter #λ(hash-ref % 'detected) (mash-hash (hash-ref verdict 'scans)))
                             #λ(> (string-length (hash-ref %1 'result))
                                  (string-length (hash-ref %2 'result))))])
          (define color (if (> p 0) "\033[91m" "\033[92m"))
          (display color)
          (define verdict (if (not (empty? results))
                             (string-append "\033[0m└ Verdict of "
                                            (symbol->string (hash-ref (second results) 'name))
                                            ": \033[1m"
                                            (hash-ref (second results) 'result) "\033[0m" color)
                             (string-append "\033[0m└ Verdict: \033[1m\033[92mClean\033[0m" color)))
          (draw-box (string-append "\033[0m"
                                   (format-hash attrs color) color "\n" 
                                   "\033[1m" positives color "\n"
                                   verdict))
          (display "\033[0m")))))

(define print-verbose? (make-parameter #t))
(define file-or-dir (command-line
                     #:program "rscan"
                     #:once-each
                     [("-n" "--not-verbose") "Compile with verbose messages"
                      (print-verbose? #f)]
                     #:args (file-or-dir)
                     (string->path file-or-dir)))

(define branch (list (file-exists? file-or-dir)
                     (directory-exists? file-or-dir)))

(unless (apply #λ(or %1 %2) branch)
  (displayln (format "Can't find file or directory '~a'"
                     (path->string file-or-dir))))

(define shas (if (and (first branch) (not (second branch)))
                 (list (read-files-sha256 (list file-or-dir)))
                 (read-directory-sha256 file-or-dir)))
(define total-positives (map (λ (names-sha i)
                               (define vt (apply virustotal-test names-sha))
                               (define fvt (if (list? (first vt)) (first vt) (list (first vt))))
                               (define svt (if (list? (second vt)) (second vt) (list (second vt))))
                               (define verbose? (if (not (print-verbose?))
                                                    #f
                                                    (= (length svt) 1))) 
                               (map display-file-verdict fvt svt
                                    (make-list (length svt) verbose?))
                               (unless (= i (- (length shas) 1))
                                 (sleep 15))
                               (map #λ(hash-ref % 'positives) svt))
                             shas (range 0 (length shas))))

(define tf (length (filter #λ(> % 0) (flatten total-positives))))
(define color (if (> tf 0) "\033[91m" "\033[92m"))
(displayln (format "~aInfected files: ~a of ~a\033[0m" color tf (length (flatten total-positives))))
