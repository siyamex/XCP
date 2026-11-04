package auth

import "time"

// SetSessionLimits changes how long a session may sit idle and how long
// it may live, for sessions checked or made from now on (ADM-SRV-05).
func (s *Service) SetSessionLimits(idle, lifetime time.Duration) {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	s.idleLimit, s.maxLifetime = idle, lifetime
}

func (s *Service) sessionIdle() time.Duration {
	s.limMu.RLock()
	defer s.limMu.RUnlock()
	if s.idleLimit > 0 {
		return s.idleLimit
	}
	return s.opt.SessionIdle
}

func (s *Service) sessionMax() time.Duration {
	s.limMu.RLock()
	defer s.limMu.RUnlock()
	if s.maxLifetime > 0 {
		return s.maxLifetime
	}
	return s.opt.SessionMax
}
