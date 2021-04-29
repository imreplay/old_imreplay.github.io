---
title: "Post about Wargames"
layout: archive
permalink: /categories/wargame
author_profile: true
sidebar: 
  nav: sidebar-main
---

{% assign posts = site.categories.Wargame| sort:"date" %}

{% for post in posts %}
  {% include archive-single.html type=page.entries_layout %}
{% endfor %}

