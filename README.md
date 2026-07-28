# x1a0m4 的部落格

這是一個使用 [Hexo](https://hexo.io/) 與 [Reimu](https://github.com/D-Sketon/hexo-theme-reimu) 主題建立的靜態部落格。

## 本機開發

```bash
npm install
npm run server
```

## 撰寫與發布

建立新文章：

```bash
npx hexo new "文章標題"
```

將變更推送到 `main` 後，GitHub Actions 會自動建置並發布至 GitHub Pages。
