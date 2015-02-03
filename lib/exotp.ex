defmodule OneTimePassword do

  defprotocol T do
    def token(t)
    def code(t, offset)
  end

  defmodule HOTP do
    defstruct issuer: nil, account_name: nil, key: ""
    def new(params \\ []) do
      t = struct(__MODULE__, params)
      %__MODULE__{t | key: t.key || :crypto.rand_bytes(20)}
    end
  end

  defmodule TOTP do
    defstruct issuer: nil, account_name: nil, period: 30, key: ""
    def new(params \\ []) do
      t = struct(__MODULE__, params)
      %__MODULE__{t | key: t.key || :crypto.rand_bytes(20)}
    end
  end

  defimpl T, for: HOTP do
    def token(t) do
      URI.encode_www_form("otpauth://hotp/#{t.issuer}:%{t.account_name}&secret=#{Base.encode32(t.key)}")
    end
    def code(t, count) do
      hs = :crypto.hmac(:sha, t.key, <<count::64>>)
      <<_::19-binary, _::4, offset::4>> = hs
      <<_::size(offset)-binary, _::1, p::31, _::binary>> = hs
      hotp = to_string(rem(p, 1000000))
      padding = String.duplicate("0", 6 - String.length(hotp))
      padding <> hotp
    end
  end

  defimpl T, for: TOTP do
    use Timex
    def token(t) do
      URI.encode_www_form("otpauth://totp/#{t.issuer}:%{t.account_name}&secret=#{Base.encode32(t.key)}?period=#{t.period}")
    end
    def code(t, offset) do
      time = div(Date.now |> Date.to_secs, t.period)
      OneTimePassword.T.code(%OneTimePassword.HOTP{key: t.key}, time + offset)
    end
  end

end
