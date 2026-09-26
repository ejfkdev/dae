// dae source-truth probe: every construct here has a hand-checkable answer.
import 'dart:async';

class Account {
  final String owner;
  int balance;
  Account(this.owner, this.balance);

  int deposit(int amount) {
    if (amount <= 0) {
      throw ArgumentError('amount must be positive');
    }
    balance = balance + amount;
    return balance;
  }

  int withdraw(int amount) {
    if (amount > balance) {
      return -1;
    } else {
      balance -= amount;
    }
    return balance;
  }

  String describe() => '$owner: $balance';
}

class SavingsAccount extends Account {
  final double rate;
  SavingsAccount(super.owner, super.balance, this.rate);

  int applyInterest() {
    balance = (balance * (1.0 + rate)).round();
    return balance;
  }
}

enum Kind { alpha, beta, gamma }

class Stack<T> {
  final List<T> items = <T>[];
  void push(T value) {
    items.add(value);
  }

  T? pop() {
    if (items.isEmpty) {
      return null;
    }
    return items.removeLast();
  }

  int get size => items.length;
}

int total(List<Account> accounts) {
  var sum = 0;
  for (final a in accounts) {
    sum += a.balance;
  }
  return sum;
}

int countAbove(List<int> values, int threshold) {
  var n = 0;
  var i = 0;
  while (i < values.length) {
    if (values[i] > threshold) {
      n++;
    } else {
      n += 0;
    }
    i++;
  }
  return n;
}

int fib(int n) => n < 2 ? n : fib(n - 1) + fib(n - 2);

String classify(int n) {
  switch (n) {
    case 0:
      return 'zero';
    case 1:
      return 'one';
    default:
      return n > 0 ? 'positive' : 'negative';
  }
}

Kind pick(int n) => n.isEven ? Kind.alpha : Kind.beta;

Map<String, int> histogram(List<String> words) {
  final counts = <String, int>{};
  for (final w in words) {
    counts[w] = (counts[w] ?? 0) + 1;
  }
  return counts;
}

int guarded(int n) {
  try {
    return n ~/ 0;
  } catch (e) {
    return -1;
  }
}

Future<int> delayedSum(List<int> values) async {
  var s = 0;
  for (final v in values) {
    s += v;
  }
  return s;
}

class Counter {
  int value = 0;
  final void Function(int) onChange;
  Counter(this.onChange);

  void bump(int by) {
    value += by;
    onChange(value);
  }
}

void main() {
  final a = Account('alice', 100);
  a.deposit(50);
  a.withdraw(30);
  print(a.describe());

  final s = SavingsAccount('bob', 1000, 0.05);
  print('interest=${s.applyInterest()}');

  final accounts = <Account>[a, s];
  print('total=${total(accounts)}');
  print('above=${countAbove(<int>[1, 5, 9, 2], 4)}');
  print('fib=${fib(10)}');
  print('classify=${classify(0)},${classify(1)},${classify(7)},${classify(-3)}');
  print('pick=${pick(4).name}');
  print('hist=${histogram(<String>['a', 'b', 'a'])}');
  print('guarded=${guarded(3)}');

  final st = Stack<int>();
  st.push(7);
  st.push(9);
  print('stack=${st.pop()} size=${st.size}');
  print('pop-empty=${Stack<String>().pop()}');

  final seen = <int>[];
  final c = Counter((v) => seen.add(v));
  c.bump(3);
  c.bump(4);
  print('counter=${c.value} seen=$seen');

  delayedSum(<int>[1, 2, 3]).then((v) => print('delayed=$v'));
}
