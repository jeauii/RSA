// RSA.cpp

#include <algorithm>
#include <string>
#include <vector>
#include <random>
#include <iostream>

using namespace std;

pair<long, long> lde(unsigned long a, unsigned long b,
	long x_a, long y_a, long x_b, long y_b)
{
	if (b == 0) return { x_a, y_a };
	long q = a / b;
	return lde(b, a - b * q,
		x_b, y_b, x_a - x_b * q, y_a - y_b * q);
}

unsigned long powmod(
	unsigned long long a, unsigned long n, unsigned long m)
{
	a %= m;
	if (n == 1) return a;
	if (a == 0) return 0;
	else if (a == 1) return 1;
	else if (a == n - 1)
		return n % 2 == 0 ? 1 : n - 1;
	return n % 2 == 0 ?
		powmod(a * a, n / 2, m) % m :
		powmod(a * a, n / 2, m) * a % m;
}

default_random_engine engine;

bool isPrime(unsigned p, int k = 1)
{
	if (p == 0 || p == 1) return false;
	if (p == 2 || p == 3 || p == 5)
		return true;
	if (p % 2 == 0 || p % 3 == 0 || p % 5 == 0)
		return false;
	uniform_int_distribution<unsigned> randInt(2, p - 1);
	unsigned s = 0, r = p - 1;
	while (r % 2 == 0) { ++s; r /= 2; }
	for (int i = 0; i < k; ++i)
	{
		unsigned a = randInt(engine);
		unsigned x = powmod(a, r, p);
		if (x != 1 && x != p - 1)
		{
			for (int j = 1; j < s; ++j)
			{
				x = x * x % p;
				if (x == 1 || x == p - 1) break;
			}
			if (x != 1 && x != p - 1)
				return false;
		}
	}
	return true;
}

unsigned randPrime(unsigned lower = 2,
	unsigned upper = UINT_MAX)
{
	uniform_int_distribution<unsigned> randInt(lower, upper);
	unsigned p;
	bool positive = false;
	do
	{
		p = randInt(engine);
		positive = isPrime(p);
		if (positive)
		{
			for (unsigned d = 7; d <= sqrt(p); d += 2)
			{
				if (p % d == 0)
				{
					positive = false;
					break;
				}
			}
		}
	} while (!positive);
	return p;
}

using Key = pair<unsigned long, unsigned long>;

class Server
{
	unsigned p, q;
	unsigned long n, e, d;
public:
	Server()
	{
		p = randPrime(32768, 65537);
		q = randPrime(32768, 65537);
		n = (unsigned long)p * q;
		setKey((unsigned long)(p - 1) * (q - 1));
	}
	Key getKey() const { return Key(e, n); }
	vector<unsigned long> decrypt(
		const vector<unsigned long> &cipher) const
	{
		vector<unsigned long> message(cipher.size());
		for (int i = 0; i < cipher.size(); ++i)
		{
			message[i] = powmod(cipher[i], d, n);
		}
		return message;
	}
private:
	void setKey(unsigned long m)
	{
		uniform_int_distribution<unsigned long> randInt(2, m - 1);
		pair<long long, long long> sol;
		do
		{
			e = randInt(engine);
			sol = lde(e, m, 1, 0, 0, 1);
		} while (e * sol.first + m * sol.second != 1);
		d = sol.first;
	}
};

class User
{
	static const int PKT_SIZE = 6;
	unsigned long e, n;
public:
	void setKey(Key key)
	{
		e = key.first; n = key.second;
	}
	vector<unsigned long> encrypt(
		const vector<unsigned long> &message) const
	{
		vector<unsigned long> cipher(message.size());
		for (int i = 0; i < message.size(); ++i)
		{
			cipher[i] = powmod(message[i], e, n);
		}
		return cipher;
	}
	static vector<unsigned long> toInteger(string str)
	{
		int packets = (str.length() - 1) / PKT_SIZE + 1;
		vector<unsigned long> arr(packets);
		unsigned long power = 1;
		for (int i = 0; i < str.length(); ++i)
		{
			if (str[i] >= 'A' && str[i] <= 'Z')
				arr[i / PKT_SIZE] += (str[i] - 64) * power;
			power *= 27;
			if (i % PKT_SIZE == PKT_SIZE - 1)
				power = 1;
		}
		return arr;
	}
	static string toString(const vector<unsigned long> &arr)
	{
		string message;
		for (int i = 0; i < arr.size(); ++i)
		{
			unsigned long n = arr[i];
			while (n > 0)
			{
				message += n % 27 == 0 ? 32 : n % 27 + 64;
				n /= 27;
			}
		}
		return message;
	}
};

int main()
{
	Server server; User user;
	user.setKey(server.getKey());
	auto message = user.toInteger("USERNAME PASSWORD");
	for (auto n : message)
		cout << n << ' ';
	cout << endl;
	cout << user.toString(message) << endl;
	auto cipher = user.encrypt(message);
	for (auto n : cipher)
		cout << n << ' ';
	cout << endl;
	cout << user.toString(cipher) << endl;
	auto original = server.decrypt(cipher);
	for (auto n : original)
		cout << n << ' ';
	cout << endl;
	cout << user.toString(original) << endl;
	return 0;
}
