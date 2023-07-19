import collections

class BasicQLearner:
    def __init__(self, q: set, d: float, l: float):
        self.Q_table = q
        self.discount_factor = d
        self.learning_rate = l

    def learn(self, last_SA, next_s, last_reward):
        last_Q = self.Q_lookup(last_SA)
        curr_state_taken = self.Q_lookup(next_s +(1,))
        curr_state_not_taken = self.Q_lookup(next_s +(0,))
        if curr_state_taken >= curr_state_not_taken:
            chosen_Q = curr_state_taken
        else:
            chosen_Q = curr_state_not_taken
        last_Q = last_Q + self.learning_rate \
            * (last_reward + self.discount_factor * chosen_Q - last_Q)
        if last_Q != 0.:
            self.Q_table[last_SA] = last_Q

    def Q_lookup(self, key):
        return self.Q_table.get(key, 0.)
