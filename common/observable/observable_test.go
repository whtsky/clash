package observable

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func iterator(item []interface{}) chan interface{} {
	ch := make(chan interface{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		for _, elm := range item {
			ch <- elm
		}
		close(ch)
	}()
	return ch
}

func TestObservable(t *testing.T) {
	iter := iterator([]interface{}{1, 2, 3, 4, 5})
	src := NewObservable(iter)
	data, err := src.Subscribe()
	assert.Nil(t, err)
	count := 0
	for range data {
		count++
	}
	assert.Equal(t, count, 5)
}

func TestObservable_MutilSubscribe(t *testing.T) {
	iter := iterator([]interface{}{1, 2, 3, 4, 5})
	src := NewObservable(iter)
	ch1, _ := src.Subscribe()
	ch2, _ := src.Subscribe()
	var count int32

	var wg sync.WaitGroup
	wg.Add(2)
	waitCh := func(ch <-chan interface{}) {
		for range ch {
			atomic.AddInt32(&count, 1)
		}
		wg.Done()
	}
	go waitCh(ch1)
	go waitCh(ch2)
	wg.Wait()
	assert.EqualValues(t, count, 10)
}

func TestObservable_UnSubscribe(t *testing.T) {
	iter := iterator([]interface{}{1, 2, 3, 4, 5})
	src := NewObservable(iter)
	data, err := src.Subscribe()
	assert.Nil(t, err)
	src.UnSubscribe(data)
	_, open := <-data
	assert.False(t, open)
}

func TestObservable_SubscribeClosedSource(t *testing.T) {
	iter := iterator([]interface{}{1})
	src := NewObservable(iter)
	data, _ := src.Subscribe()
	<-data

	_, closed := src.Subscribe()
	assert.NotNil(t, closed)
}

func TestObservable_UnSubscribeWithNotExistSubscription(t *testing.T) {
	sub := Subscription(make(chan interface{}))
	iter := iterator([]interface{}{1})
	src := NewObservable(iter)
	src.UnSubscribe(sub)
}

func TestObservable_SubscribeGoroutineLeak(t *testing.T) {
	iter := iterator([]interface{}{1, 2, 3, 4, 5})
	src := NewObservable(iter)
	max := 100

	var list []Subscription
	for i := 0; i < max; i++ {
		ch, _ := src.Subscribe()
		list = append(list, ch)
	}

	var wg sync.WaitGroup
	wg.Add(max)
	waitCh := func(ch <-chan interface{}) {
		for range ch {
		}
		wg.Done()
	}

	for _, ch := range list {
		go waitCh(ch)
	}
	wg.Wait()

	for _, sub := range list {
		_, more := <-sub
		assert.False(t, more)
	}

	_, more := <-list[0]
	assert.False(t, more)
}
