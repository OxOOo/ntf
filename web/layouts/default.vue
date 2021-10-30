<template>
  <div>
    <a-layout>
      <a-layout-content class="main">
        <div class="content">
          <Nuxt />
        </div>
      </a-layout-content>
    </a-layout>
  </div>
</template>

<style scoped>
.main {
    min-width: 100vw;
    min-height: 100vh;
}
.content {
    padding-top: 100px;
    max-width: 800px;
    margin-left: auto;
    margin-right: auto;
}
</style>
