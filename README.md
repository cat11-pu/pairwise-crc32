# crc32

一个只依赖 Python 标准库的校验与分帧内核：把载荷封成带长度字段和校验值的帧，
把帧解回载荷，并给一整段记录里的坏帧定位。全部在内存里完成，不读文件、不联网、
不看时钟、不用随机源，同一串调用永远得到同一批结果。

帧的布局：

    +--------------+-----------+------------------+
    | 长度 (2 字节) | 载荷       | 校验值 (4 字节)   |
    | 大端          | N 字节     | 大端              |
    +--------------+-----------+------------------+

长度字段写的就是载荷的字节数，所以最短的帧只有六个字节，空载荷也是合法的帧，
单个载荷最多 4096 字节。校验值是长度字段加整段载荷的反射 CRC-32：多项式
0xEDB88320、寄存器先预置成 0xFFFFFFFF、算完再异或 0xFFFFFFFF，与公开的
CRC-32 标准向量一致，例如 123456789 的校验值是 0xCBF43926。

## 目录

- crc32/core.py：查表、校验值、封帧解帧、整段分帧与坏帧定位
- tests/test_core.py：行为测试

## 接口速览

```python
from crc32.core import crc32, crc_table, declared_length
from crc32.core import encode_frame, decode_frame, split_frames, locate_bad_frames

crc32(b"123456789")                  # 0xCBF43926
crc32(b"6789", crc32(b"12345"))      # 与整段一次算出的一样

raw = encode_frame(b"hello")         # 长度字段 + 载荷 + 校验值
payload, end = decode_frame(raw)     # 解一帧，end 是下一帧的起点
split_frames(raw + raw)              # 整段缓冲区里的每一段载荷
locate_bad_frames(recording)         # 每一处坏帧的起始偏移，全都好时是空表
```

校验值可以接力：把上一次的返回值传回第二个参数，分块喂入与整段一次算出的结果
相同。解帧失败一律抛 `FrameError`，异常里的 `offset` 指向出问题的帧；载荷超限、
校验值对不上、缓冲区尾部不满一帧都会被报出来，不会静默丢字节。

## 跑测试

在项目根目录执行：

    python3 -m unittest discover -s tests -v
