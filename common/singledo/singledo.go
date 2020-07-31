package singledo

import (
	"sync"
	"time"
)

type Single struct {
	mux    sync.RWMutex
	wait   time.Duration
	next   time.Time
	result *Result
}

type Result struct {
	Val interface{}
	Err error
}

// add lock outside
func (s *Single) shouldRun() bool {
	now := time.Now()
	return !now.Before(s.next)
}

func (s *Single) Do(fn func() (interface{}, error)) (v interface{}, err error, shared bool) {
	s.mux.RLock()
	shouldRun := s.shouldRun()
	s.mux.RUnlock()
	if !shouldRun {
		return s.result.Val, s.result.Err, true
	}

	s.mux.Lock()
	defer s.mux.Unlock()
	if !s.shouldRun() {
		return s.result.Val, s.result.Err, true
	}
	val, err := fn()
	s.result = &Result{val, err}
	s.next = time.Now().Add(s.wait)
	return val, err, false
}

func (s *Single) Reset() {
	s.mux.Lock()
	s.next = time.Time{}
	s.mux.Unlock()
}

func NewSingle(wait time.Duration) *Single {
	return &Single{wait: wait}
}
