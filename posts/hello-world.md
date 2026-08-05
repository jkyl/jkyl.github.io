# Hello, World

This is a test post to verify that all markdown features render correctly in the terminal style.

## Text Formatting

Here's some **bold text** and *italic text* and ***bold italic***. You can also use `inline code` to highlight things like `variable_name` or `function()`.

## Code Blocks

A Python example:

```python
def fibonacci(n):
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

print(fibonacci(10))  # 55
```

And a shell command:

```bash
curl -s https://api.example.com/data | jq '.results[]'
```

## Lists

Unordered:

- First item
- Second item
  - Nested item
  - Another nested item
- Third item

Ordered:

1. Step one
2. Step two
3. Step three

## Blockquote

> The best way to predict the future is to invent it.
>
> — Alan Kay

## Links and Images

Here's a [link to GitHub](https://github.com/jkyl).

![placeholder](images/placeholder.png)

## Table

| Model | Parameters | FID |
|-------|-----------|-----|
| BigGAN | 70M | 7.4 |
| StyleGAN2 | 30M | 2.8 |
| DiT-XL/2 | 675M | 2.3 |

## Horizontal Rule

---

That's all the markdown features. If everything above is styled correctly, the blog is working.
